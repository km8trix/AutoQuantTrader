"""Derive callback risk values from explicitly authenticated original sources.

This pure adapter does not sample a clock, inspect SQL, normalize a market source
or apply accounting. The concrete reader independently replays its retained
source-only request through the sole engine before accepting these values.
"""

import re
from dataclasses import dataclass, replace
from datetime import datetime
from decimal import Decimal
from typing import Literal, Protocol

from packages.domain.accounting_contracts import AccountSnapshot
from packages.domain.continuous_runtime_source_contracts import ContinuousRuntimeSourceDescriptor
from packages.domain.daily_runtime_contracts import (
    RUNTIME_ROLES,
    DailyRuntimeRiskEvidence,
    RuntimeObligationInventory,
    RuntimeRiskAssignment,
    RuntimeRiskInputRefs,
    RuntimeRiskSource,
    RuntimeRole,
)
from packages.domain.daily_runtime_risk import (
    build_daily_runtime_evidence,
    runtime_source_value_sha256,
)
from packages.domain.engine_contracts import DailyIntentBatch
from packages.domain.personal_contracts import require_utc
from packages.domain.reconciliation_contracts import ReconciliationHeads, ReconciliationResult


@dataclass(frozen=True, slots=True)
class RuntimeSourceCondition:
    """An authenticator's original assessment; construction grants no authority."""

    role: RuntimeRole
    source_at: datetime
    received_at: datetime
    valid_until: datetime
    revision: int
    status: Literal["available", "blocked", "unavailable"]
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        for value in (self.source_at, self.received_at, self.valid_until):
            require_utc(value, "runtime source assessment time")
        if (
            self.role not in RUNTIME_ROLES
            or self.source_at > self.received_at
            or type(self.revision) is not int
            or not 0 <= self.revision < 2**63
            or self.status not in ("available", "blocked", "unavailable")
            or (self.status == "available") != (not self.reasons)
            or self.reasons != tuple(sorted(set(self.reasons)))
            or any(re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", reason) is None for reason in self.reasons)
        ):
            raise ValueError("RUNTIME_SOURCE_CONDITION_INVALID")


class ContinuousRuntimeRoleEvaluator(Protocol):
    def evaluate(
        self,
        *,
        snapshot: AccountSnapshot,
        batch: DailyIntentBatch,
        phase: Literal["decision", "activation"],
        evaluated_at: datetime,
        request_rows: tuple[tuple[datetime, bool], ...],
    ) -> tuple[RuntimeSourceCondition, ...]:
        """Pure role evaluation on previously resolved, original source evidence."""
        ...


class ContinuousRuntimeEvidencePort:
    def __init__(
        self,
        *,
        descriptor: ContinuousRuntimeSourceDescriptor,
        assignment: RuntimeRiskAssignment,
        obligations: RuntimeObligationInventory,
        original_heads: ReconciliationHeads,
        cash_restrictions: Decimal | None,
        reconciliation: ReconciliationResult | None,
        evaluator: ContinuousRuntimeRoleEvaluator,
    ) -> None:
        if (
            descriptor.request_kind == "initialize"
            or descriptor.assignment_sha256 != assignment.semantic_sha256
            or descriptor.scope.account_id != assignment.account_id
            or descriptor.scope.account_binding_sha256 != assignment.account_binding_sha256
            or descriptor.producer_map.semantic_sha256 != assignment.producer_map_sha256
            or descriptor.obligations_sha256 != obligations.semantic_sha256
            or original_heads.capacity_sha256 != obligations.semantic_sha256
            or original_heads.lease_generation != descriptor.captured_fence.fence.fencing_generation
            or not callable(getattr(evaluator, "evaluate", None))
        ):
            raise ValueError("RUNTIME_EVIDENCE_ORIGINAL_BINDING_DIFFERS")
        self.descriptor, self.assignment, self.obligations = descriptor, assignment, obligations
        self.original_heads, self.cash_restrictions, self.reconciliation = (
            original_heads,
            cash_restrictions,
            reconciliation,
        )
        self.evaluator = evaluator

    def build(
        self,
        *,
        snapshot: AccountSnapshot,
        batch: DailyIntentBatch,
        phase: Literal["decision", "activation"],
        evaluated_at: datetime,
        accepted_intent_ids: tuple[str, ...],
        daily_return: Decimal | None,
        drawdown: Decimal | None,
        request_rows: tuple[tuple[datetime, bool], ...],
    ) -> DailyRuntimeRiskEvidence:
        original = self.descriptor
        if (
            evaluated_at != original.original_checked_at
            or snapshot.point.knowledge_at > evaluated_at
            or (phase == "decision" and snapshot.point.knowledge_at != evaluated_at)
            or snapshot.account_id != original.scope.account_id
            or batch.snapshot_sha256 != snapshot.semantic_sha256
            or (phase == "activation") != (original.request_kind == "activation_dependencies")
        ):
            raise ValueError("RUNTIME_CALLBACK_ORIGINAL_BOUNDARY_DIFFERS")
        heads = replace(
            self.original_heads,
            ledger_sha256=snapshot.journal_sha256,
            order_sha256=snapshot.order_sha256,
        )
        refs = RuntimeRiskInputRefs(
            snapshot_sha256=snapshot.semantic_sha256,
            assignment_sha256=self.assignment.semantic_sha256,
            heads=heads,
            phase=phase,
            source_session=batch.target.trigger.source_session,
            execution_session=batch.target.trigger.execution_session,
            sources=(),
            obligations=self.obligations,
            reconciliation=self.reconciliation,
            accepted_intent_ids=accepted_intent_ids,
            daily_return=daily_return,
            drawdown=drawdown,
            cash_restrictions=self.cash_restrictions,
        )
        conditions = self.evaluator.evaluate(
            snapshot=snapshot,
            batch=batch,
            phase=phase,
            evaluated_at=evaluated_at,
            request_rows=request_rows,
        )
        if type(conditions) is not tuple or any(
            type(v) is not RuntimeSourceCondition for v in conditions
        ):
            raise ValueError("RUNTIME_AUTHENTICATOR_RESULT_TYPE")
        if len({v.role for v in conditions}) != len(conditions):
            raise ValueError("RUNTIME_AUTHENTICATOR_DUPLICATE_ROLE")
        by_role = {condition.role: condition for condition in conditions}
        sources = []
        for producer in original.producer_map.producers:
            condition = by_role.get(producer.role)
            if condition is None:
                # The shared validator explicitly reports missing roles. Do not
                # manufacture a clock/provider observation time for an unknown.
                continue
            # Preserve the original authenticator interval; evaluation never
            # refreshes it.
            sources.append(
                RuntimeRiskSource(
                    spec=producer,
                    account_id=original.scope.account_id,
                    account_binding_sha256=original.scope.account_binding_sha256,
                    source_id=original.descriptor_id,
                    source_sha256=original.semantic_sha256,
                    value_sha256=runtime_source_value_sha256(producer.role, snapshot, batch, refs),
                    revision=condition.revision,
                    source_at=condition.source_at,
                    received_at=condition.received_at,
                    valid_until=condition.valid_until,
                    status=condition.status,
                    reasons=condition.reasons,
                )
            )
        refs = replace(refs, sources=tuple(sources))
        return build_daily_runtime_evidence(
            self.assignment,
            snapshot,
            batch,
            refs,
            producer_map=original.producer_map,
            evaluated_at=evaluated_at,
        )
