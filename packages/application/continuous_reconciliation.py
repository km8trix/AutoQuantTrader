"""Resolve canonical comparison values from the actual continuous checkpoint.

Durable source and account-journal authentication remains the transaction reader's
responsibility. This resolver never reads a supplied observed cash/position value
as the expected coordinator state and never rewrites the retained checkpoint.
"""

from packages.domain.accounting_contracts import AccountingContext, ExecutionAccountingPort
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_account_contracts import CanonicalAccountTransitionRef
from packages.domain.continuous_engine_contracts import ContinuousEngineInputs
from packages.domain.personal_contracts import ContractRecord, ReductionPoint
from packages.domain.reconciliation_persistence_contracts import ResolvedReconciliationTransition


class ContinuousReconciliationTransitionResolver:
    def __init__(self, *, accounting: ExecutionAccountingPort) -> None:
        self.accounting = accounting

    def resolve_transition(
        self, reference: CanonicalAccountTransitionRef, value: ContractRecord
    ) -> ResolvedReconciliationTransition:
        if (
            type(value) is not CausalEngineCheckpoint
            or type(value.inputs) is not ContinuousEngineInputs
        ):
            raise ValueError("CONTINUOUS_CHECKPOINT_REQUIRED")
        spec = value.inputs.spec
        if (
            value.semantic_sha256 != reference.checkpoint_sha256
            or spec.account_id != reference.account_id
            or spec.account_binding_sha256 != reference.account_binding_sha256
            or value.now != reference.applied_at
            or spec.environment != reference.environment
        ):
            raise ValueError("CONTINUOUS_TRANSITION_BINDING_DIFFERS")
        # Comparison has its own fact-stage context. A retained stage-8 valuation
        # does not become a stage-1 projection just because its time is equal.
        context = AccountingContext(
            run_id=spec.run_id,
            point=ReductionPoint(value.frontier, value.sequence, reference.applied_at, 1),
            economic_at=value.economic,
            event_id=reference.command_id,
            expected_mark_session=value.mark_session,
            instruments=spec.instruments,
        )
        current = self.accounting.project(
            state=value.state, context=context, policy=spec.execution_policy
        )
        return ResolvedReconciliationTransition(reference, current, context, spec.execution_policy)
