"""Historical, non-authorizing attestation of paper-account enrollment.

Phase 5I reauthenticates the configured credential reference against the exact
durable terminal account binding.  The resulting attestation deliberately
retains only digests and the terminal sequence.  It does not make the
historical account-status observation current and grants no control, broker,
exposure, re-arm, or strategy-invocation authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAccountIdentityContinuityReceipt,
    AlpacaPaperCredentialReference,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.models import require_utc

PAPER_ACCOUNT_ENROLLMENT_ATTESTATION_CONTRACT_VERSION = (
    "phase5-paper-account-enrollment-attestation-v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PaperAccountEnrollmentAttestationError(RuntimeError):
    """Configured paper-account enrollment could not be authenticated exactly."""


class PaperAccountEnrollmentIdentityRepository(Protocol):
    """Authenticate the configured reference against its durable terminal binding."""

    def authenticate_configured_terminal_identity(
        self,
        reference: AlpacaPaperCredentialReference,
        checked_at: datetime,
    ) -> AlpacaPaperAccountIdentityContinuityReceipt | None: ...


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise PaperAccountEnrollmentAttestationError(
            f"{field_name} must be a lowercase SHA-256 digest"
        )
    return value


def _require_checked_at(value: object) -> datetime:
    if type(value) is not datetime:
        raise PaperAccountEnrollmentAttestationError(
            "paper-account enrollment checked_at must be an exact UTC datetime"
        )
    try:
        require_utc(value, "paper-account enrollment checked_at")
    except (AttributeError, TypeError, ValueError):
        raise PaperAccountEnrollmentAttestationError(
            "paper-account enrollment checked_at must be an exact UTC datetime"
        ) from None
    return value


def _require_reference(value: object) -> AlpacaPaperCredentialReference:
    if type(value) is not AlpacaPaperCredentialReference:
        raise PaperAccountEnrollmentAttestationError(
            "paper-account enrollment requires an exact Alpaca paper credential reference"
        )
    try:
        value.__post_init__()
    except Exception:
        raise PaperAccountEnrollmentAttestationError(
            "paper-account enrollment credential reference is invalid"
        ) from None
    return value


@dataclass(frozen=True, slots=True, init=False)
class PaperAccountEnrollmentAttestation:
    """Digest-only proof of one configured historical terminal enrollment."""

    binding_sha256: str
    credential_reference_sha256: str
    identity_receipt_sha256: str
    sequence_number: int

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "PaperAccountEnrollmentAttestation must be produced by attest_paper_account_enrollment"
        )

    def _validate(self) -> None:
        _require_sha256(
            self.binding_sha256,
            "paper-account enrollment binding digest",
        )
        _require_sha256(
            self.credential_reference_sha256,
            "paper-account enrollment credential-reference digest",
        )
        _require_sha256(
            self.identity_receipt_sha256,
            "paper-account enrollment identity-receipt digest",
        )
        if type(self.sequence_number) is not int or self.sequence_number <= 0:
            raise PaperAccountEnrollmentAttestationError(
                "paper-account enrollment terminal sequence must be positive"
            )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    PAPER_ACCOUNT_ENROLLMENT_ATTESTATION_CONTRACT_VERSION,
                    "historical_paper_account_enrollment_attestation",
                    self.binding_sha256,
                    self.credential_reference_sha256,
                    self.identity_receipt_sha256,
                    self.sequence_number,
                )
            )
        ).hexdigest()

    @property
    def status(self) -> str:
        return "historical_paper_account_enrollment_attested_non_authorizing"

    @property
    def historical(self) -> bool:
        return True

    @property
    def current(self) -> bool:
        return False

    @property
    def account_status_current(self) -> bool:
        return False

    @property
    def binding_fresh(self) -> bool:
        return False

    @property
    def operational_control_authenticated(self) -> bool:
        return False

    @property
    def broker_action_authorized(self) -> bool:
        return False

    @property
    def new_exposure_authorized(self) -> bool:
        return False

    @property
    def automatic_rearm_authorized(self) -> bool:
        return False

    @property
    def strategy_invocation_authorized(self) -> bool:
        return False

    @property
    def public_payload(self) -> dict[str, object]:
        """Return a log-safe projection without account IDs or timestamps."""

        self._validate()
        return {
            "account_status_current": self.account_status_current,
            "automatic_rearm_authorized": self.automatic_rearm_authorized,
            "binding_fresh": self.binding_fresh,
            "binding_sha256": self.binding_sha256,
            "broker_action_authorized": self.broker_action_authorized,
            "contract_version": PAPER_ACCOUNT_ENROLLMENT_ATTESTATION_CONTRACT_VERSION,
            "credential_reference_sha256": self.credential_reference_sha256,
            "current": self.current,
            "historical": self.historical,
            "identity_receipt_sha256": self.identity_receipt_sha256,
            "new_exposure_authorized": self.new_exposure_authorized,
            "operational_control_authenticated": self.operational_control_authenticated,
            "sequence_number": self.sequence_number,
            "status": self.status,
            "strategy_invocation_authorized": self.strategy_invocation_authorized,
        }


def attest_paper_account_enrollment(
    reference: AlpacaPaperCredentialReference,
    *,
    repository: PaperAccountEnrollmentIdentityRepository,
    checked_at: datetime,
) -> PaperAccountEnrollmentAttestation:
    """Authenticate and reduce one configured terminal identity to historical proof."""

    reference = _require_reference(reference)
    checked_at = _require_checked_at(checked_at)
    try:
        authenticate = getattr(
            repository,
            "authenticate_configured_terminal_identity",
            None,
        )
    except Exception:
        raise PaperAccountEnrollmentAttestationError(
            "configured paper-account terminal identity authentication failed"
        ) from None
    if not callable(authenticate):
        raise PaperAccountEnrollmentAttestationError(
            "paper-account enrollment repository does not implement configured "
            "terminal identity authentication"
        )

    try:
        receipt = authenticate(reference, checked_at)
    except Exception:
        raise PaperAccountEnrollmentAttestationError(
            "configured paper-account terminal identity authentication failed"
        ) from None
    if receipt is None:
        raise PaperAccountEnrollmentAttestationError(
            "configured paper-account enrollment history is absent"
        )
    if type(receipt) is not AlpacaPaperAccountIdentityContinuityReceipt:
        raise PaperAccountEnrollmentAttestationError(
            "configured paper-account identity repository returned invalid evidence"
        )
    try:
        receipt._validate()
        reference_sha256 = reference.semantic_sha256
        receipt_sha256 = receipt.semantic_sha256
    except Exception:
        raise PaperAccountEnrollmentAttestationError(
            "configured paper-account identity evidence is malformed"
        ) from None

    if (
        receipt.account_id != reference.account_id
        or receipt.expected_provider_account_id != reference.expected_provider_account_id
        or receipt.credential_reference_sha256 != reference_sha256
        or receipt.checked_at != checked_at
    ):
        raise PaperAccountEnrollmentAttestationError(
            "configured paper-account identity evidence conflicts with the "
            "requested account, provider, credential reference, or check instant"
        )

    attestation = object.__new__(PaperAccountEnrollmentAttestation)
    for field_name, value in (
        ("binding_sha256", receipt.binding_sha256),
        ("credential_reference_sha256", reference_sha256),
        ("identity_receipt_sha256", receipt_sha256),
        ("sequence_number", receipt.sequence_number),
    ):
        object.__setattr__(attestation, field_name, value)
    attestation._validate()
    return attestation


__all__ = [
    "PAPER_ACCOUNT_ENROLLMENT_ATTESTATION_CONTRACT_VERSION",
    "PaperAccountEnrollmentAttestation",
    "PaperAccountEnrollmentAttestationError",
    "PaperAccountEnrollmentIdentityRepository",
    "attest_paper_account_enrollment",
]
