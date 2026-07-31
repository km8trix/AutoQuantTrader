"""Application workflow for source-scoped, non-applying broker inbox admission."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from packages.adapters.broker.alpaca_paper_inbox import (
    AlpacaPaperInboxError,
    create_alpaca_paper_inbox_admission_request,
)
from packages.domain.broker_inbox import (
    BrokerInboxError,
    BrokerInboxNonApplicationDecisionReceipt,
    BrokerInboxRepository,
)
from packages.domain.broker_reconciliation import (
    BrokerReconciliationError,
    BrokerReconciliationFact,
)


class BrokerInboxAdmissionError(RuntimeError):
    """An authenticated reconciliation source could not be admitted safely."""


class BrokerInboxAdmissionSourceMissing(BrokerInboxAdmissionError):
    """The requested immutable Phase 4K source is absent."""


class BrokerInboxAdmissionSourceConflict(BrokerInboxAdmissionError):
    """Loaded or returned inbox evidence conflicts with its immutable source."""


class BrokerReconciliationFactLoader(Protocol):
    """Load one fully authenticated Phase 4K reconciliation fact."""

    def load(self, fact_id: str) -> BrokerReconciliationFact | None: ...


def admit_authenticated_alpaca_paper_reconciliation_fact(
    fact_id: str,
    *,
    reconciliation_loader: BrokerReconciliationFactLoader,
    inbox_repository: BrokerInboxRepository,
) -> BrokerInboxNonApplicationDecisionReceipt:
    """Admit one exact Phase 4K fact and retain its non-application decision."""

    if type(fact_id) is not str or len(fact_id) != 36 or fact_id != fact_id.strip():
        raise BrokerInboxAdmissionError(
            "broker inbox reconciliation fact ID must be a canonical UUID"
        )
    try:
        parsed_fact_id = UUID(fact_id)
    except ValueError as error:
        raise BrokerInboxAdmissionError(
            "broker inbox reconciliation fact ID must be a canonical UUID"
        ) from error
    if str(parsed_fact_id) != fact_id:
        raise BrokerInboxAdmissionError(
            "broker inbox reconciliation fact ID must be a canonical UUID"
        )
    for port, method_name, port_name in (
        (reconciliation_loader, "load", "reconciliation loader"),
        (inbox_repository, "record", "broker inbox repository"),
    ):
        if not callable(getattr(port, method_name, None)):
            raise BrokerInboxAdmissionError(f"{port_name} does not implement {method_name}")

    try:
        source_fact = reconciliation_loader.load(fact_id)
    except (BrokerReconciliationError, TypeError, ValueError) as error:
        raise BrokerInboxAdmissionSourceConflict(
            "broker inbox reconciliation source failed authentication"
        ) from error
    if source_fact is None:
        raise BrokerInboxAdmissionSourceMissing("broker inbox reconciliation source is absent")
    if type(source_fact) is not BrokerReconciliationFact:
        raise BrokerInboxAdmissionSourceConflict(
            "reconciliation loader returned a non-canonical Phase 4K fact"
        )
    try:
        source_fact._validate()
        if source_fact.fact_id != fact_id:
            raise BrokerInboxAdmissionSourceConflict(
                "reconciliation loader returned a different Phase 4K identity"
            )
        request = create_alpaca_paper_inbox_admission_request(source_fact)
        decision = inbox_repository.record(request)
    except BrokerInboxAdmissionError:
        raise
    except (
        AlpacaPaperInboxError,
        BrokerInboxError,
        BrokerReconciliationError,
        TypeError,
        ValueError,
    ) as error:
        raise BrokerInboxAdmissionSourceConflict(
            "broker inbox admission or durable append failed"
        ) from error

    if type(decision) is not BrokerInboxNonApplicationDecisionReceipt:
        raise BrokerInboxAdmissionSourceConflict(
            "broker inbox repository returned a non-canonical decision"
        )
    try:
        decision._validate()
    except (BrokerInboxError, BrokerReconciliationError, TypeError, ValueError) as error:
        raise BrokerInboxAdmissionSourceConflict(
            "broker inbox repository returned invalid durable evidence"
        ) from error
    if decision.request != request:
        raise BrokerInboxAdmissionSourceConflict(
            "broker inbox repository changed the admission request"
        )
    return decision


__all__ = [
    "BrokerInboxAdmissionError",
    "BrokerInboxAdmissionSourceConflict",
    "BrokerInboxAdmissionSourceMissing",
    "BrokerReconciliationFactLoader",
    "admit_authenticated_alpaca_paper_reconciliation_fact",
]
