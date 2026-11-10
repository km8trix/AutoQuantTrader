"""Pure, non-applying broker inbox admission decisions.

Phase 4L assigns source-scoped identities to already-authenticated Phase 4K
reconciliation facts.  A point lookup does not expose a qualified immutable
provider revision identity, so even an economically and security-matched order
is withheld rather than converted into a lifecycle or execution fact.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from packages.domain.broker_reconciliation import (
    BrokerReconciliationEvidence,
    BrokerReconciliationFact,
    BrokerReconciliationOutcome,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc

BROKER_INBOX_CONTRACT_VERSION = "phase4l-source-scoped-broker-inbox-admission-v1"
BROKER_INBOX_IDENTITY_PROFILE_ID = "phase4l-authenticated-lookup-source-scoped-identity-v1"
BROKER_INBOX_NON_APPLICATION_POLICY_ID = "phase4l-authenticated-lookup-non-application-v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BrokerInboxError(ValueError):
    """Broker inbox evidence violates the frozen admission contract."""


class BrokerInboxConflict(BrokerInboxError):
    """A stable inbox identity conflicts with immutable source evidence."""


class BrokerInboxSourceKind(StrEnum):
    """Closed authenticated source kinds admitted by the Phase 4L slice."""

    AUTHENTICATED_CLIENT_ORDER_LOOKUP = "authenticated_client_order_lookup"


class BrokerInboxDisposition(StrEnum):
    """Closed non-applying decisions for Phase 4K historical evidence."""

    WITHHELD_UNQUALIFIED_REVISION_IDENTITY = "withheld_unqualified_revision_identity"
    QUARANTINED_ECONOMIC_MISMATCH = "quarantined_economic_mismatch"
    QUARANTINED_SECURITY_MISMATCH = "quarantined_security_mismatch"
    INCONCLUSIVE_NOT_VISIBLE = "inconclusive_not_visible"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


BROKER_INBOX_IDENTITY_PROFILE_SHA256 = _semantic_sha256(
    (
        BROKER_INBOX_CONTRACT_VERSION,
        "identity_profile",
        BROKER_INBOX_IDENTITY_PROFILE_ID,
        BrokerInboxSourceKind.AUTHENTICATED_CLIENT_ORDER_LOOKUP,
        "one_authenticated_phase4k_fact_and_digest_per_observation",
        "no_cross_source_deduplication",
        "no_provider_revision_identity",
    )
)
BROKER_INBOX_NON_APPLICATION_POLICY_SHA256 = _semantic_sha256(
    (
        BROKER_INBOX_CONTRACT_VERSION,
        "non_application_policy",
        BROKER_INBOX_NON_APPLICATION_POLICY_ID,
        tuple(BrokerInboxDisposition),
        "no_lifecycle_or_execution_target",
        "all_authority_withheld",
    )
)


def _require_text(
    value: object,
    field_name: str,
    *,
    maximum: int = 256,
) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BrokerInboxError(
            f"{field_name} must be bounded, trimmed text without control characters"
        )
    return value


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise BrokerInboxError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise BrokerInboxError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise BrokerInboxError(str(error)) from error
    return value


class _NoBrokerInboxAuthority:
    __slots__ = ()

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def normalized_fact_authorized(self) -> bool:
        return False

    @property
    def inbox_application_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_application_authorized(self) -> bool:
        return False

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def broker_call_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class BrokerInboxHistoricalObservationIdentity(_NoBrokerInboxAuthority):
    """A local source identity that makes no provider-revision claim."""

    account_id: str
    provider_id: str
    environment: str
    source_kind: BrokerInboxSourceKind
    identity_profile_id: str
    identity_profile_sha256: str
    source_reconciliation_fact_id: str
    source_reconciliation_fact_sha256: str
    source_lookup_receipt_id: str
    source_lookup_receipt_sha256: str
    source_ingress_receipt_id: str
    source_ingress_receipt_sha256: str
    source_observation_sha256: str

    def __post_init__(self) -> None:
        for value, field_name, maximum in (
            (self.account_id, "inbox identity account ID", 64),
            (self.provider_id, "inbox identity provider ID", 128),
            (self.environment, "inbox identity environment", 32),
            (
                self.identity_profile_id,
                "inbox identity profile ID",
                128,
            ),
            (
                self.source_reconciliation_fact_id,
                "inbox identity source reconciliation fact ID",
                128,
            ),
            (
                self.source_lookup_receipt_id,
                "inbox identity source lookup receipt ID",
                128,
            ),
            (
                self.source_ingress_receipt_id,
                "inbox identity source ingress receipt ID",
                128,
            ),
        ):
            _require_text(value, field_name, maximum=maximum)
        if type(self.source_kind) is not BrokerInboxSourceKind:
            raise BrokerInboxError("inbox identity source kind is unsupported")
        if (
            self.identity_profile_id != BROKER_INBOX_IDENTITY_PROFILE_ID
            or self.identity_profile_sha256 != BROKER_INBOX_IDENTITY_PROFILE_SHA256
        ):
            raise BrokerInboxError("inbox identity does not pin the frozen source-scoped profile")
        for digest, field_name in (
            (
                self.identity_profile_sha256,
                "inbox identity profile digest",
            ),
            (
                self.source_reconciliation_fact_sha256,
                "inbox identity source reconciliation fact digest",
            ),
            (
                self.source_lookup_receipt_sha256,
                "inbox identity source lookup receipt digest",
            ),
            (
                self.source_ingress_receipt_sha256,
                "inbox identity source ingress receipt digest",
            ),
            (
                self.source_observation_sha256,
                "inbox identity source observation digest",
            ),
        ):
            _require_sha256(digest, field_name)

    @property
    def observation_id(self) -> str:
        return canonical_id(
            "broker-inbox-historical-observation",
            self.provider_id,
            self.environment,
            self.identity_profile_id,
            self.identity_profile_sha256,
            self.source_reconciliation_fact_id,
            self.source_reconciliation_fact_sha256,
        )

    @property
    def provider_revision_id(self) -> None:
        return None

    @property
    def source_scoped(self) -> bool:
        return True

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BROKER_INBOX_CONTRACT_VERSION,
            "historical_observation_identity",
            self.observation_id,
            self.account_id,
            self.provider_id,
            self.environment,
            self.source_kind,
            self.identity_profile_id,
            self.identity_profile_sha256,
            self.source_reconciliation_fact_id,
            self.source_reconciliation_fact_sha256,
            self.source_lookup_receipt_id,
            self.source_lookup_receipt_sha256,
            self.source_ingress_receipt_id,
            self.source_ingress_receipt_sha256,
            self.source_observation_sha256,
            self.provider_revision_id,
            self.provider_revision_identity_qualified,
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(self._semantic_material())


@dataclass(frozen=True, slots=True, init=False)
class BrokerInboxAdmissionRequest(_NoBrokerInboxAuthority):
    """Exact Phase 4K source proposed to the non-applying inbox decision."""

    identity: BrokerInboxHistoricalObservationIdentity
    source_fact: BrokerReconciliationFact

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("BrokerInboxAdmissionRequest must be proof-constructed")

    def _validate(self) -> None:
        if type(self.identity) is not BrokerInboxHistoricalObservationIdentity:
            raise BrokerInboxError("inbox admission request requires an exact historical identity")
        if type(self.source_fact) is not BrokerReconciliationFact:
            raise BrokerInboxError("inbox admission request requires an exact reconciliation fact")
        self.identity.__post_init__()
        self.source_fact._validate()
        evidence = self.source_fact.evidence
        expected = (
            (self.identity.account_id, evidence.account_id),
            (self.identity.provider_id, evidence.provider_id),
            (self.identity.environment, evidence.environment),
            (
                self.identity.source_reconciliation_fact_id,
                self.source_fact.fact_id,
            ),
            (
                self.identity.source_reconciliation_fact_sha256,
                self.source_fact.semantic_sha256,
            ),
            (
                self.identity.source_lookup_receipt_id,
                evidence.source_lookup_receipt_id,
            ),
            (
                self.identity.source_lookup_receipt_sha256,
                evidence.source_lookup_receipt_sha256,
            ),
            (
                self.identity.source_ingress_receipt_id,
                evidence.source_ingress_receipt_id,
            ),
            (
                self.identity.source_ingress_receipt_sha256,
                evidence.source_ingress_receipt_sha256,
            ),
            (
                self.identity.source_observation_sha256,
                evidence.source_observation_sha256,
            ),
        )
        if any(actual != wanted for actual, wanted in expected):
            raise BrokerInboxConflict(
                "inbox admission identity conflicts with its exact Phase 4K source"
            )

    @property
    def request_id(self) -> str:
        return canonical_id(
            "broker-inbox-admission-request",
            self.identity.observation_id,
            self.source_fact.semantic_sha256,
        )

    @property
    def source_evidence(self) -> BrokerReconciliationEvidence:
        return self.source_fact.evidence

    @property
    def source_evidence_sha256(self) -> str:
        return self.source_fact.evidence.semantic_sha256

    @property
    def source_evidence_payload(self) -> tuple[object, ...]:
        """Return the exact Phase 4K semantic payload without reinterpretation."""

        return self.source_fact.evidence._semantic_material()

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BROKER_INBOX_CONTRACT_VERSION,
            "admission_request",
            self.request_id,
            self.identity.semantic_sha256,
            self.source_fact.fact_id,
            self.source_fact.semantic_sha256,
            self.source_evidence_sha256,
            self.source_evidence_payload,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())


def _broker_inbox_admission_request(
    source_fact: BrokerReconciliationFact,
    identity: BrokerInboxHistoricalObservationIdentity,
) -> BrokerInboxAdmissionRequest:
    """Construct a request only from exact authenticated Phase 4K evidence."""

    if type(source_fact) is not BrokerReconciliationFact:
        raise BrokerInboxError("inbox admission request construction requires an exact source fact")
    if type(identity) is not BrokerInboxHistoricalObservationIdentity:
        raise BrokerInboxError(
            "inbox admission request construction requires an exact source identity"
        )
    request = object.__new__(BrokerInboxAdmissionRequest)
    object.__setattr__(request, "identity", identity)
    object.__setattr__(request, "source_fact", source_fact)
    request._validate()
    return request


def _expected_disposition(
    request: BrokerInboxAdmissionRequest,
) -> BrokerInboxDisposition:
    outcome = request.source_fact.evidence.outcome
    mapping = {
        BrokerReconciliationOutcome.ORDER_OBSERVED_CANDIDATE: (
            BrokerInboxDisposition.WITHHELD_UNQUALIFIED_REVISION_IDENTITY
        ),
        BrokerReconciliationOutcome.QUARANTINED_ECONOMIC_MISMATCH: (
            BrokerInboxDisposition.QUARANTINED_ECONOMIC_MISMATCH
        ),
        BrokerReconciliationOutcome.QUARANTINED_SECURITY_MISMATCH: (
            BrokerInboxDisposition.QUARANTINED_SECURITY_MISMATCH
        ),
        BrokerReconciliationOutcome.INCONCLUSIVE_NOT_VISIBLE: (
            BrokerInboxDisposition.INCONCLUSIVE_NOT_VISIBLE
        ),
    }
    try:
        return mapping[outcome]
    except (KeyError, TypeError):
        raise BrokerInboxError(
            "inbox admission request has an unsupported reconciliation outcome"
        ) from None


@dataclass(frozen=True, slots=True, init=False)
class BrokerInboxNonApplicationDecisionReceipt(_NoBrokerInboxAuthority):
    """Explicit proof that the historical source was not applied."""

    request: BrokerInboxAdmissionRequest
    disposition: BrokerInboxDisposition
    policy_id: str
    policy_sha256: str
    decided_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("BrokerInboxNonApplicationDecisionReceipt must be reducer-produced")

    def _validate(self) -> None:
        if type(self.request) is not BrokerInboxAdmissionRequest:
            raise BrokerInboxError("inbox decision requires an exact admission request")
        self.request._validate()
        if type(self.disposition) is not BrokerInboxDisposition:
            raise BrokerInboxError("inbox decision disposition is unsupported")
        if (
            self.policy_id != BROKER_INBOX_NON_APPLICATION_POLICY_ID
            or self.policy_sha256 != BROKER_INBOX_NON_APPLICATION_POLICY_SHA256
        ):
            raise BrokerInboxError("inbox decision does not pin the frozen non-application policy")
        if self.disposition is not _expected_disposition(self.request):
            raise BrokerInboxConflict(
                "inbox decision conflicts with its exact reconciliation outcome"
            )
        decided_at = _require_utc(self.decided_at, "inbox decision decided_at")
        if decided_at < self.request.source_fact.normalized_at:
            raise BrokerInboxConflict(
                "inbox decision cannot predate its normalized Phase 4K source"
            )

    @property
    def decision_id(self) -> str:
        return canonical_id(
            "broker-inbox-non-application-decision",
            self.request.request_id,
            self.policy_id,
            self.policy_sha256,
        )

    @property
    def application_withheld(self) -> bool:
        return True

    @property
    def quarantined(self) -> bool:
        return self.disposition in {
            BrokerInboxDisposition.QUARANTINED_ECONOMIC_MISMATCH,
            BrokerInboxDisposition.QUARANTINED_SECURITY_MISMATCH,
        }

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BROKER_INBOX_CONTRACT_VERSION,
            "non_application_decision",
            self.decision_id,
            self.request.request_id,
            self.request.semantic_sha256,
            self.disposition,
            self.policy_id,
            self.policy_sha256,
            self.decided_at,
            self.application_withheld,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())


def _broker_inbox_non_application_decision(
    request: BrokerInboxAdmissionRequest,
    disposition: BrokerInboxDisposition,
    *,
    decided_at: datetime,
) -> BrokerInboxNonApplicationDecisionReceipt:
    """Construct a deterministic non-application receipt for one request."""

    if type(request) is not BrokerInboxAdmissionRequest:
        raise BrokerInboxError("inbox decision construction requires an exact admission request")
    receipt = object.__new__(BrokerInboxNonApplicationDecisionReceipt)
    object.__setattr__(receipt, "request", request)
    object.__setattr__(receipt, "disposition", disposition)
    object.__setattr__(
        receipt,
        "policy_id",
        BROKER_INBOX_NON_APPLICATION_POLICY_ID,
    )
    object.__setattr__(
        receipt,
        "policy_sha256",
        BROKER_INBOX_NON_APPLICATION_POLICY_SHA256,
    )
    object.__setattr__(receipt, "decided_at", decided_at)
    receipt._validate()
    return receipt


def decide_broker_inbox_admission(
    request: BrokerInboxAdmissionRequest,
    *,
    decided_at: datetime,
) -> BrokerInboxNonApplicationDecisionReceipt:
    """Return the only closed non-applying decision for an exact request."""

    if type(request) is not BrokerInboxAdmissionRequest:
        raise BrokerInboxError(
            "inbox admission decision requires an exact proof-constructed request"
        )
    request._validate()
    return _broker_inbox_non_application_decision(
        request,
        _expected_disposition(request),
        decided_at=decided_at,
    )


@dataclass(frozen=True, slots=True)
class BrokerInboxAdmissionBundle(_NoBrokerInboxAuthority):
    """Repository-ready request and its exact non-application decision."""

    request: BrokerInboxAdmissionRequest
    decision: BrokerInboxNonApplicationDecisionReceipt

    def __post_init__(self) -> None:
        if type(self.request) is not BrokerInboxAdmissionRequest:
            raise BrokerInboxError("inbox bundle requires an exact admission request")
        if type(self.decision) is not BrokerInboxNonApplicationDecisionReceipt:
            raise BrokerInboxError("inbox bundle requires an exact non-application decision")
        self.request._validate()
        self.decision._validate()
        if self.decision.request != self.request:
            raise BrokerInboxConflict("inbox bundle decision conflicts with its exact request")

    @property
    def bundle_id(self) -> str:
        return canonical_id(
            "broker-inbox-admission-bundle",
            self.request.request_id,
            self.decision.decision_id,
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(
            (
                BROKER_INBOX_CONTRACT_VERSION,
                "admission_bundle",
                self.bundle_id,
                self.request.semantic_sha256,
                self.decision.semantic_sha256,
            )
        )


class BrokerInboxRepository(Protocol):
    """Durably retain source-scoped non-application decisions."""

    def record(
        self,
        request: BrokerInboxAdmissionRequest,
    ) -> BrokerInboxNonApplicationDecisionReceipt:
        """Decide and record an exact request, or return its durable retry."""

    def load(
        self,
        decision_id: str,
    ) -> BrokerInboxNonApplicationDecisionReceipt | None:
        """Load one authenticated non-application decision."""

    def history(
        self,
        account_id: str,
    ) -> tuple[BrokerInboxNonApplicationDecisionReceipt, ...]:
        """Return one authenticated account-local decision history."""


__all__ = [
    "BROKER_INBOX_CONTRACT_VERSION",
    "BROKER_INBOX_IDENTITY_PROFILE_ID",
    "BROKER_INBOX_IDENTITY_PROFILE_SHA256",
    "BROKER_INBOX_NON_APPLICATION_POLICY_ID",
    "BROKER_INBOX_NON_APPLICATION_POLICY_SHA256",
    "BrokerInboxAdmissionBundle",
    "BrokerInboxAdmissionRequest",
    "BrokerInboxConflict",
    "BrokerInboxDisposition",
    "BrokerInboxError",
    "BrokerInboxHistoricalObservationIdentity",
    "BrokerInboxNonApplicationDecisionReceipt",
    "BrokerInboxRepository",
    "BrokerInboxSourceKind",
    "decide_broker_inbox_admission",
]
