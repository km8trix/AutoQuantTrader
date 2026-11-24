"""The canonical engine's atomic pure commitment preparation loop.

Returned transitions are prospective values. The caller owns their atomic commit,
trace, due-event scheduling, accepted-intent registry and any outbound effect.
"""

from dataclasses import dataclass, replace
from decimal import Decimal
from typing import Literal

from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingState,
    AccountingTransition,
    AccountSnapshot,
    Commitment,
    ExecutionAccountingPort,
    ExecutionPolicy,
    InstallCommitment,
)
from packages.domain.decimal_math import exact_decimal_add as add
from packages.domain.decimal_math import exact_decimal_multiply as mul
from packages.domain.engine_contracts import DailyIntentBatch, DailyRiskDecision, DailyRiskPolicy
from packages.domain.identifiers import canonical_id
from packages.domain.order_reducer import create_order_submission
from packages.domain.personal_contracts import ContractRecord


@dataclass(frozen=True, slots=True)
class PreparedDailyCommitments(ContractRecord):
    state: AccountingState
    transitions: tuple[AccountingTransition, ...]
    commitments: tuple[Commitment, ...]
    last_reduction_sequence: int
    disposition: Literal["installed", "rolled_back", "no_intents"]
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(PreparedDailyCommitments, self).__post_init__()
        if self.last_reduction_sequence < 0:
            raise ValueError("preparation sequence must be nonnegative")
        if self.disposition == "installed":
            if (
                not self.transitions
                or len(self.transitions) != len(self.commitments)
                or self.reasons
            ):
                raise ValueError("installed preparation requires its complete transition batch")
            if self.state != self.transitions[-1].state:
                raise ValueError("prepared state differs from final transition")
        elif self.transitions or self.commitments:
            raise ValueError("failed/empty preparation cannot retain partial effects")
        if (self.disposition == "rolled_back") != bool(self.reasons):
            raise ValueError("preparation disposition and reasons differ")


def prepare_daily_commitments(
    *,
    state: AccountingState,
    snapshot: AccountSnapshot,
    batch: DailyIntentBatch,
    decision: DailyRiskDecision,
    context: AccountingContext,
    execution_policy: ExecutionPolicy,
    risk_policy: DailyRiskPolicy,
    accounting: ExecutionAccountingPort,
    attempt_namespace: Literal["model-attempt", "daily-runtime-attempt"] = "model-attempt",
) -> PreparedDailyCommitments:
    """Prepare exact ordered installs, retaining no partial state on failure."""
    for value, expected in (
        (state, AccountingState),
        (snapshot, AccountSnapshot),
        (batch, DailyIntentBatch),
        (decision, DailyRiskDecision),
        (context, AccountingContext),
        (execution_policy, ExecutionPolicy),
        (risk_policy, DailyRiskPolicy),
    ):
        if type(value) is not expected:
            raise ValueError("commitment preparation requires exact immutable contracts")
    if attempt_namespace not in ("model-attempt", "daily-runtime-attempt"):
        raise ValueError("unsupported commitment attempt namespace")
    if (
        not decision.approved
        or decision.reasons
        or decision.batch != batch
        or decision.policy_sha256 != risk_policy.semantic_sha256
        or batch.snapshot_sha256 != snapshot.semantic_sha256
        or snapshot.state_sha256 != state.semantic_sha256
        or snapshot.account_id != state.account_id
        or snapshot.point.knowledge_at > context.point.knowledge_at
        or snapshot.point.reduction_sequence > context.point.reduction_sequence
        or snapshot.point.frontier_sequence > context.point.frontier_sequence
    ):
        raise ValueError("approved decision, current state and source snapshot must bind exactly")
    holds, shares = dict(decision.reserved_cash_by_intent), dict(decision.reserved_shares_by_intent)
    ids = tuple(intent.intent_id for intent in batch.intents)
    if (
        len(set(ids)) != len(ids)
        or set(holds) != set(ids)
        or len(holds) != len(decision.reserved_cash_by_intent)
        or len(shares) != len(decision.reserved_shares_by_intent)
        or set(shares)
        != {intent.intent_id for intent in batch.intents if intent.side.value == "sell"}
    ):
        raise ValueError("approved reserve inventory must match the exact intent batch")
    sequence = context.point.reduction_sequence
    if not batch.intents:
        return PreparedDailyCommitments(state, (), (), sequence, "no_intents")
    current = state
    transitions: list[AccountingTransition] = []
    commitments: list[Commitment] = []
    for intent in batch.intents:
        sequence += 1
        try:
            submission = create_order_submission(
                intent=intent,
                risk_decision_id=decision.semantic_sha256,
                submission_attempt_id=canonical_id(attempt_namespace, intent.intent_id),
                submitted_at=context.point.knowledge_at,
            )
            commitment = Commitment(
                canonical_id("commitment", intent.intent_id),
                intent.intent_id,
                submission.order_id,
                intent.instrument_id,
                intent.symbol,
                intent.side,
                intent.quantity,
                Decimal(0),
                intent.quantity,
                holds[intent.intent_id],
                shares.get(intent.intent_id, Decimal(0)),
                mul(intent.reference_price, add(Decimal(1), risk_policy.adverse_reserve_fraction)),
                mul(intent.quantity, risk_policy.fee_per_share),
                batch.target.trigger.source_session,
                batch.target.trigger.execution_session,
                sequence,
                batch.target.not_before,
                batch.target.expires_at,
                decision.policy_sha256,
                snapshot.semantic_sha256,
            )
            command = AccountingCommand(
                commitment.commitment_id, InstallCommitment(submission, commitment)
            )
            step = replace(
                context,
                event_id=command.command_id,
                point=replace(context.point, reduction_sequence=sequence, stage=6),
                approved_snapshot=snapshot,
                risk_policy_sha256=risk_policy.semantic_sha256,
            )
            result = accounting.advance(
                state=current, command=command, context=step, policy=execution_policy
            )
        except Exception as error:
            return PreparedDailyCommitments(
                state,
                (),
                (),
                sequence,
                "rolled_back",
                ("INSTALL_EXCEPTION:" + type(error).__name__,),
            )
        if result.disposition != "applied":
            return PreparedDailyCommitments(
                state, (), (), sequence, "rolled_back", result.reasons or ("INSTALL_NOT_APPLIED",)
            )
        current = result.state
        transitions.append(result)
        commitments.append(commitment)
    return PreparedDailyCommitments(
        current, tuple(transitions), tuple(commitments), sequence, "installed"
    )
