"""Observed fact batches for the sole continuous engine, without source authority."""

from dataclasses import dataclass
from typing import ClassVar

from packages.domain.personal_contracts import ContractRecord, require_digest
from packages.domain.reconciliation_application_contracts import ReconciliationFactCommand
from packages.domain.reconciliation_contracts import (
    MAX_RECONCILIATION_ITEMS,
    MAX_RECONCILIATION_PAGES,
    FactApplication,
    ReconciliationPage,
    ReconciliationScope,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ContinuousReconciliationBatch(ContractRecord):
    """One retained source closure; each command keeps its own economic instant.

    Source authentication and original application-time proof remain the durable
    composer's responsibility. The engine applies only planned observed facts;
    this value cannot authorize an attempt, release, adoption or control change.
    """

    contract_version: ClassVar[str] = "personal-continuous-reconciliation/1"
    scope: ReconciliationScope
    facts: tuple[ReconciliationFactCommand, ...]
    source_receipts: tuple[ReconciliationPage, ...]
    prior_applications: tuple[FactApplication, ...]
    source_order: tuple[str, ...]
    source_closure_sha256: str

    def __post_init__(self) -> None:
        super(ContinuousReconciliationBatch, self).__post_init__()
        require_digest(self.source_closure_sha256, "retained reconciliation closure")
        if self.scope.source_class != "stateful_simulation":
            raise ValueError("continuous reconciliation requires its separate modeled venue")
        for values, limit, expected in (
            (self.facts, MAX_RECONCILIATION_ITEMS, ReconciliationFactCommand),
            (self.source_receipts, MAX_RECONCILIATION_PAGES, ReconciliationPage),
            (self.prior_applications, MAX_RECONCILIATION_ITEMS, FactApplication),
        ):
            if (
                type(values) is not tuple
                or len(values) > limit
                or any(type(value) is not expected for value in values)
            ):
                raise ValueError("continuous reconciliation requires bounded exact records")
        if any(item.scope != self.scope for item in self.facts):
            raise ValueError("continuous reconciliation fact account differs")
        if (
            type(self.source_order) is not tuple
            or len(self.source_order) > MAX_RECONCILIATION_ITEMS
            or len(self.source_order) != len(set(self.source_order))
            or set(self.source_order) != {item.observation.fact_id for item in self.facts}
        ):
            raise ValueError("continuous reconciliation requires the complete source order")
        ids = tuple(item.fact_id for item in self.prior_applications)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("continuous reconciliation application history must be unique")
