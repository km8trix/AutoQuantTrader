"""Immutable source-bound commands and outcomes for observed fact application.

These records establish structural links only. Retained-source authentication,
account fencing, durable history and economic application are separate duties.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingState,
    AccountingTransition,
)
from packages.domain.identifiers import canonical_id
from packages.domain.personal_contracts import require_digest
from packages.domain.reconciliation_contracts import (
    MAX_RECONCILIATION_ITEMS,
    FactApplication,
    FactObservation,
    ReconciliationOrderBinding,
    ReconciliationRecord,
    ReconciliationScope,
    require_reconciliation_id,
)


def reconciliation_command_id(scope: ReconciliationScope, observation: FactObservation) -> str:
    """An overlap delivery does not change the canonical application identity."""
    return canonical_id(
        "applied-reconciliation-command/1",
        scope.semantic_sha256,
        observation.fact_id,
        observation.fact_sha256,
    )


@dataclass(frozen=True, slots=True)
class ReconciliationFactCommand(ReconciliationRecord):
    scope: ReconciliationScope
    observation: FactObservation
    command: AccountingCommand
    source_sha256: str
    mapping: ReconciliationOrderBinding | None
    predecessor_fact_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(ReconciliationFactCommand, self).__post_init__()
        require_digest(self.source_sha256, "retained page identity")
        if len(self.predecessor_fact_ids) > 16 or self.predecessor_fact_ids != tuple(
            sorted(set(self.predecessor_fact_ids))
        ):
            raise ValueError("fact requires bounded sorted unique predecessors")
        for predecessor in self.predecessor_fact_ids:
            require_reconciliation_id(predecessor, "fact predecessor")
        if self.observation.fact_id in self.predecessor_fact_ids:
            raise ValueError("fact cannot depend on itself")


@dataclass(frozen=True, slots=True, kw_only=True)
class ReconciliationFactPlan(ReconciliationRecord):
    """Pure source planning, without financial application or durable authority."""

    scope: ReconciliationScope
    initial_state_sha256: str
    context: AccountingContext
    candidates: tuple[ReconciliationFactCommand, ...]
    prior_applications: tuple[FactApplication, ...]
    quarantined_fact_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    source_order: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(ReconciliationFactPlan, self).__post_init__()
        require_digest(self.initial_state_sha256, "planning state")
        identities = tuple(item.observation.fact_id for item in self.candidates)
        if len(identities) > MAX_RECONCILIATION_ITEMS or identities != tuple(
            sorted(set(identities))
        ):
            raise ValueError("plan candidates require bounded unique identities")
        prior = tuple(item.fact_id for item in self.prior_applications)
        if len(prior) > MAX_RECONCILIATION_ITEMS or prior != tuple(sorted(set(prior))):
            raise ValueError("plan applications require bounded unique identities")
        for values in (self.quarantined_fact_ids, self.reasons):
            if len(values) > MAX_RECONCILIATION_ITEMS or values != tuple(sorted(set(values))):
                raise ValueError("plan dispositions require bounded sorted unique values")
        if not set(self.quarantined_fact_ids) <= set(identities):
            raise ValueError("quarantine refers to an absent plan candidate")
        if self.source_order and (
            self.scope.source_class != "stateful_simulation"
            or len(set(self.source_order)) != len(self.source_order)
            or set(self.source_order) != set(identities)
        ):
            raise ValueError("source order must cover exact plan inventory")
        if self.context.point.stage != 1:
            raise ValueError("reconciliation planning requires a fact-stage context")


@dataclass(frozen=True, slots=True)
class ReconciliationCandidateCheck(ReconciliationRecord):
    disposition: Literal["apply", "duplicate", "unresolved", "quarantined"]
    application: FactApplication | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        super(ReconciliationCandidateCheck, self).__post_init__()
        if (self.application is not None) != (self.disposition == "duplicate"):
            raise ValueError("only an actual duplicate retains its original application")
        if (self.reason is not None) != (self.disposition in {"unresolved", "quarantined"}):
            raise ValueError("blocked candidate requires its explicit reason")


@dataclass(frozen=True, slots=True)
class AppliedReconciliationBatch(ReconciliationRecord):
    state: AccountingState
    current: AccountingTransition
    applications: tuple[FactApplication, ...]
    duplicate_fact_ids: tuple[str, ...]
    unresolved_fact_ids: tuple[str, ...]
    quarantined_fact_ids: tuple[str, ...]
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        super(AppliedReconciliationBatch, self).__post_init__()
        if self.current.state != self.state:
            raise ValueError("application result must retain its actual canonical state")
        if len(self.applications) > MAX_RECONCILIATION_ITEMS:
            raise ValueError("application result exceeds item bound")
        applied = tuple(item.fact_id for item in self.applications)
        if applied != tuple(sorted(set(applied))):
            raise ValueError("application results require sorted unique fact identities")
        for values in (
            self.duplicate_fact_ids,
            self.unresolved_fact_ids,
            self.quarantined_fact_ids,
            self.reasons,
        ):
            if len(values) > MAX_RECONCILIATION_ITEMS or values != tuple(sorted(set(values))):
                raise ValueError("application outcome requires bounded sorted unique identities")
            for value in values:
                require_reconciliation_id(value, "application outcome")
        if not set(self.duplicate_fact_ids) <= set(applied):
            raise ValueError("duplicate result must retain actual application links")
        if set(applied) & (set(self.unresolved_fact_ids) | set(self.quarantined_fact_ids)) or set(
            self.unresolved_fact_ids
        ) & set(self.quarantined_fact_ids):
            raise ValueError("application disposition identities overlap")
