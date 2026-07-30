"""Pure Alpaca paper mapping into the non-applying broker inbox.

Only an authenticated Phase 4K reconciliation fact is accepted.  The adapter
assigns a local source-scoped observation identity and deliberately withholds a
matched order because the point lookup does not establish a stable immutable
provider revision identity.
"""

from __future__ import annotations

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_ADAPTER_ID,
    AlpacaPaperContractError,
)
from packages.domain.broker_inbox import (
    BROKER_INBOX_IDENTITY_PROFILE_ID,
    BROKER_INBOX_IDENTITY_PROFILE_SHA256,
    BrokerInboxAdmissionRequest,
    BrokerInboxHistoricalObservationIdentity,
    BrokerInboxSourceKind,
    _broker_inbox_admission_request,
)
from packages.domain.broker_reconciliation import (
    BrokerReconciliationFact,
    BrokerReconciliationOutcome,
)

ALPACA_PAPER_INBOX_CONTRACT_VERSION = "phase4l-alpaca-paper-source-scoped-inbox-admission-v1"


class AlpacaPaperInboxError(AlpacaPaperContractError):
    """An Alpaca paper inbox source violates the frozen adapter contract."""


class AlpacaPaperInboxConflict(AlpacaPaperInboxError):
    """An Alpaca paper inbox source conflicts with authenticated Phase 4K evidence."""


def _require_authenticated_lookup_fact(
    source_fact: BrokerReconciliationFact,
) -> BrokerReconciliationFact:
    if type(source_fact) is not BrokerReconciliationFact:
        raise AlpacaPaperInboxError(
            "Alpaca inbox admission requires an exact Phase 4K reconciliation fact"
        )
    try:
        source_fact._validate()
        _ = source_fact.semantic_sha256
    except (TypeError, ValueError) as error:
        raise AlpacaPaperInboxError(
            "Alpaca inbox source fact failed deterministic authentication"
        ) from error
    evidence = source_fact.evidence
    if evidence.provider_id != ALPACA_PAPER_ADAPTER_ID or evidence.environment != "paper":
        raise AlpacaPaperInboxConflict(
            "Alpaca inbox source must remain scoped to the paper adapter"
        )
    if evidence.outcome not in {
        BrokerReconciliationOutcome.ORDER_OBSERVED_CANDIDATE,
        BrokerReconciliationOutcome.QUARANTINED_ECONOMIC_MISMATCH,
        BrokerReconciliationOutcome.QUARANTINED_SECURITY_MISMATCH,
        BrokerReconciliationOutcome.INCONCLUSIVE_NOT_VISIBLE,
    }:
        raise AlpacaPaperInboxConflict("Alpaca inbox source has an unsupported historical outcome")
    return source_fact


def create_alpaca_paper_inbox_admission_request(
    source_fact: BrokerReconciliationFact,
) -> BrokerInboxAdmissionRequest:
    """Map an authenticated Phase 4K fact to a source-scoped inbox request."""

    fact = _require_authenticated_lookup_fact(source_fact)
    evidence = fact.evidence
    identity = BrokerInboxHistoricalObservationIdentity(
        account_id=evidence.account_id,
        provider_id=evidence.provider_id,
        environment=evidence.environment,
        source_kind=BrokerInboxSourceKind.AUTHENTICATED_CLIENT_ORDER_LOOKUP,
        identity_profile_id=BROKER_INBOX_IDENTITY_PROFILE_ID,
        identity_profile_sha256=BROKER_INBOX_IDENTITY_PROFILE_SHA256,
        source_reconciliation_fact_id=fact.fact_id,
        source_reconciliation_fact_sha256=fact.semantic_sha256,
        source_lookup_receipt_id=evidence.source_lookup_receipt_id,
        source_lookup_receipt_sha256=evidence.source_lookup_receipt_sha256,
        source_ingress_receipt_id=evidence.source_ingress_receipt_id,
        source_ingress_receipt_sha256=evidence.source_ingress_receipt_sha256,
        source_observation_sha256=evidence.source_observation_sha256,
    )
    return _broker_inbox_admission_request(fact, identity)


__all__ = [
    "ALPACA_PAPER_INBOX_CONTRACT_VERSION",
    "AlpacaPaperInboxConflict",
    "AlpacaPaperInboxError",
    "create_alpaca_paper_inbox_admission_request",
]
