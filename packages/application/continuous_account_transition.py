"""Prepare account checkpoints through the sole engine, outside durable locks.

The prepared identity proves only that this preparer ran the engine. The storage
composer must independently authenticate source closure, account heads and risk
admissions and publish all resulting state/holds/commands atomically.
"""

from dataclasses import dataclass, field
from typing import Literal
from weakref import WeakValueDictionary, finalize

from packages.application.causal_engine import (
    advance_continuous_engine_with_applications,
    apply_continuous_runtime_action,
    initialize_continuous_engine,
)
from packages.domain.accounting_contracts import ExecutionAccountingPort
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import (
    ClosedEngineFrontier,
    ContinuousDecision,
    ContinuousEngineInputs,
    ContinuousRiskEvidencePort,
)
from packages.domain.continuous_runtime_action import ContinuousRuntimeAction
from packages.domain.engine_contracts import DailyStrategy
from packages.domain.personal_contracts import content_digest, require_digest
from packages.domain.reconciliation_application_contracts import AppliedReconciliationBatch
from packages.domain.research_job_contracts import require_identifier


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedContinuousTransition:
    command_id: str
    command_sha256: str
    request: ContinuousEngineInputs | ClosedEngineFrontier | ContinuousRuntimeAction
    previous_checkpoint_sha256: str | None
    checkpoint: CausalEngineCheckpoint
    source_closure_sha256: str
    new_decisions: tuple[ContinuousDecision, ...]
    application_batches: tuple[AppliedReconciliationBatch, ...]
    disposition: Literal["initialized", "advanced", "runtime_action", "idempotent"]
    seal: object = field(repr=False, compare=False)


def _fingerprint(value: PreparedContinuousTransition) -> str:
    return content_digest(
        (
            value.command_id,
            value.command_sha256,
            value.request.semantic_sha256,
            value.previous_checkpoint_sha256,
            value.checkpoint.semantic_sha256,
            value.source_closure_sha256,
            tuple(decision.semantic_sha256 for decision in value.new_decisions),
            tuple(batch.semantic_sha256 for batch in value.application_batches),
            value.disposition,
        )
    )


class ContinuousAccountTransitionPreparer:
    def __init__(
        self,
        *,
        accounting: ExecutionAccountingPort,
        strategy: DailyStrategy,
        runtime_evidence: ContinuousRiskEvidencePort,
    ) -> None:
        if not callable(getattr(runtime_evidence, "build", None)):
            raise ValueError("EXPLICIT_CONTINUOUS_RUNTIME_EVIDENCE_REQUIRED")
        self.accounting, self.strategy, self.runtime_evidence = (
            accounting,
            strategy,
            runtime_evidence,
        )
        self._seal = object()
        self._owned: WeakValueDictionary[int, PreparedContinuousTransition] = WeakValueDictionary()
        self._fingerprints: dict[int, str] = {}

    def _own(self, value: PreparedContinuousTransition) -> PreparedContinuousTransition:
        self._owned[id(value)] = value
        self._fingerprints[id(value)] = _fingerprint(value)
        finalize(value, self._fingerprints.pop, id(value), None)
        return value

    def require_prepared(self, value: PreparedContinuousTransition) -> None:
        """Call outside SQL: canonical fingerprints may traverse the checkpoint."""
        if type(value) is not PreparedContinuousTransition or (
            value.seal is not self._seal
            or self._owned.get(id(value)) is not value
            or self._fingerprints.get(id(value)) != _fingerprint(value)
        ):
            raise ValueError("OWNED_CONTINUOUS_ENGINE_PREPARATION_REQUIRED")

    def prepare_initialize(
        self,
        *,
        command_id: str,
        inputs: ContinuousEngineInputs,
        source_closure_sha256: str,
    ) -> PreparedContinuousTransition:
        require_identifier(command_id, "continuous initialization command")
        require_digest(source_closure_sha256, "retained bootstrap source closure")
        checkpoint = initialize_continuous_engine(
            inputs,
            accounting=self.accounting,
            strategy=self.strategy,
            runtime_evidence=self.runtime_evidence,
        )
        if checkpoint.runtime_decisions:
            raise ValueError("CONTINUOUS_INITIALIZATION_CANNOT_ADMIT_EXPOSURE")
        return self._own(
            PreparedContinuousTransition(
                command_id,
                content_digest(("continuous-initialize/1", inputs, source_closure_sha256)),
                inputs,
                None,
                checkpoint,
                source_closure_sha256,
                (),
                (),
                "initialized",
                self._seal,
            )
        )

    def prepare_frontier(
        self,
        *,
        command_id: str,
        checkpoint: CausalEngineCheckpoint,
        frontier: ClosedEngineFrontier,
    ) -> PreparedContinuousTransition:
        require_identifier(command_id, "continuous frontier command")
        previous = checkpoint.semantic_sha256
        result, applications = advance_continuous_engine_with_applications(
            checkpoint,
            frontier,
            expected_sha256=previous,
            accounting=self.accounting,
            strategy=self.strategy,
            runtime_evidence=self.runtime_evidence,
        )
        count = len(checkpoint.runtime_decisions)
        if result.runtime_decisions[:count] != checkpoint.runtime_decisions:
            raise ValueError("CONTINUOUS_ENGINE_REPLACED_DECISION_HISTORY")
        return self._own(
            PreparedContinuousTransition(
                command_id,
                content_digest(("continuous-frontier/1", frontier)),
                frontier,
                previous,
                result,
                frontier.source_frontier_sha256,
                result.runtime_decisions[count:],
                applications,
                "idempotent" if result is checkpoint else "advanced",
                self._seal,
            )
        )

    def prepare_runtime_action(
        self,
        *,
        command_id: str,
        checkpoint: CausalEngineCheckpoint,
        action: ContinuousRuntimeAction,
    ) -> PreparedContinuousTransition:
        require_identifier(command_id, "continuous runtime action command")
        previous = checkpoint.semantic_sha256
        result = apply_continuous_runtime_action(
            checkpoint,
            action,
            expected_sha256=previous,
            accounting=self.accounting,
            strategy=self.strategy,
            runtime_evidence=self.runtime_evidence,
        )
        if result.runtime_decisions != checkpoint.runtime_decisions:
            raise ValueError("runtime action changed original engine decision history")
        return self._own(
            PreparedContinuousTransition(
                command_id,
                content_digest(("continuous-runtime-action/1", action)),
                action,
                previous,
                result,
                action.source_closure_sha256,
                (),
                (),
                "idempotent" if result is checkpoint else "runtime_action",
                self._seal,
            )
        )
