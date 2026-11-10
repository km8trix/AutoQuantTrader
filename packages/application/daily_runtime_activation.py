"""Prepare one atomic runtime reserve activation; no venue acceptance or delivery."""

from dataclasses import dataclass, replace
from decimal import Decimal

from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingState,
    AccountingTransition,
    ActivateRuntimeCommitments,
    Commitment,
    ExecutionAccountingPort,
    ExecutionPolicy,
    RuntimeActivationTerms,
)
from packages.domain.daily_attempt import prepare_daily_dispatch
from packages.domain.daily_attempt_contracts import CanonicalDailyAttempt, DailyDispatchRecord
from packages.domain.decimal_math import exact_decimal_add as add
from packages.domain.decimal_math import exact_decimal_multiply as multiply
from packages.domain.identifiers import canonical_id
from packages.domain.models import Side
from packages.domain.personal_contracts import ContractRecord


@dataclass(frozen=True, slots=True)
class PreparedDailyRuntimeActivation(ContractRecord):
    command: AccountingCommand
    transition: AccountingTransition
    commitments: tuple[Commitment, ...]

    def __post_init__(self) -> None:
        super(PreparedDailyRuntimeActivation, self).__post_init__()
        if type(self.command.payload) is not ActivateRuntimeCommitments:
            raise ValueError("runtime preparation has a different command")
        ids = tuple(term.commitment_id for term in self.command.payload.terms)
        if (
            self.transition.disposition != "applied"
            or self.transition.reasons
            or self.transition.journal_entries
            or self.transition.due_events
            or tuple(c.commitment_id for c in self.commitments) != ids
            or any(c not in self.transition.state.commitments for c in self.commitments)
        ):
            raise ValueError("runtime preparation requires the complete observed-only transition")


def prepare_daily_runtime_activation(
    *,
    state: AccountingState,
    context: AccountingContext,
    execution_policy: ExecutionPolicy,
    attempts: tuple[CanonicalDailyAttempt, ...],
    dispatches: tuple[DailyDispatchRecord, ...],
    accounting: ExecutionAccountingPort,
) -> PreparedDailyRuntimeActivation:
    """Recompute every first-send record and apply their complete common risk batch once.

    The caller authenticates retained source bytes and commits the prospective
    state, hold revisions and dispatch journal atomically. This return is data.
    """
    for value, cls in (
        (state, AccountingState),
        (context, AccountingContext),
        (execution_policy, ExecutionPolicy),
    ):
        if type(value) is not cls:
            raise ValueError("runtime activation requires exact immutable inputs")
    if (
        type(attempts) is not tuple
        or type(dispatches) is not tuple
        or not 1 <= len(attempts) == len(dispatches) <= 4
        or any(type(item) is not CanonicalDailyAttempt for item in attempts)
        or any(type(item) is not DailyDispatchRecord for item in dispatches)
    ):
        raise ValueError("runtime activation requires a bounded exact attempt/dispatch inventory")
    by_id = {attempt.attempt_id: attempt for attempt in attempts}
    if len(by_id) != len(attempts):
        raise ValueError("runtime attempt inventory repeats an identity")
    first = dispatches[0].activation
    snapshot, decision, evidence = first.snapshot, first.decision, first.evidence
    policy = evidence.assignment.policy
    ids = {intent.intent_id for intent in decision.batch.intents}
    if (
        execution_policy.model_id != "observed-facts-v1"
        or snapshot.state_sha256 != state.semantic_sha256
        or snapshot.account_id != state.account_id
        or context.approved_snapshot != snapshot
        or context.risk_policy_sha256 != policy.semantic_sha256
        or context.point.reduction_sequence <= snapshot.point.reduction_sequence
        or context.point.frontier_sequence < snapshot.point.frontier_sequence
        or context.point.knowledge_at < first.checked_at
        or context.expected_mark_session != evidence.execution_session
        or len(ids) != len(dispatches)
        or {item.preparation.request.submission.intent.intent_id for item in dispatches} != ids
        or {item.preparation.attempt_id for item in dispatches} != set(by_id)
    ):
        raise ValueError("runtime activation differs from its complete current risk batch")
    before = accounting.project(state=state, context=context, policy=execution_policy)
    if replace(before.snapshot, point=snapshot.point) != snapshot:
        raise ValueError("runtime activation snapshot is not the canonical current projection")
    cash = dict(decision.reserved_cash_by_intent)
    shares = dict(decision.reserved_shares_by_intent)
    marks = {mark.instrument_id: mark for mark in snapshot.marks}
    terms = []
    for dispatch in dispatches:
        activation = dispatch.activation
        attempt = by_id[dispatch.preparation.attempt_id]
        if (
            activation.snapshot != snapshot
            or activation.decision != decision
            or activation.evidence != evidence
            or activation.heads != first.heads
            or activation.fence != first.fence
            or activation.checked_at != first.checked_at
            or not dispatch.dispatched_at <= context.point.knowledge_at < activation.expires_at
            or dispatch
            != prepare_daily_dispatch(
                attempt=attempt,
                activation=activation,
                command_id=dispatch.command_id,
                dispatched_at=dispatch.dispatched_at,
            )
        ):
            raise ValueError("runtime dispatch does not bind the exact common fresh activation")
        current = activation.current_hold.commitment
        if current not in state.commitments:
            raise ValueError("runtime activation lost its exact current commitment")
        mark = marks[current.instrument_id]
        # BUY reserve includes the existing adverse fraction; SELL reserves fees,
        # retaining its selected bid as the price reference, without a cash credit.
        price = (
            multiply(mark.price, add(Decimal(1), policy.adverse_reserve_fraction))
            if current.side is Side.BUY
            else mark.price
        )
        terms.append(
            RuntimeActivationTerms(
                commitment_id=current.commitment_id,
                expected_commitment_sha256=current.semantic_sha256,
                reserved_cash=cash[current.intent_id],
                reserved_sell_quantity=shares.get(current.intent_id, Decimal(0)),
                approved_price=price,
                remaining_fee_budget=multiply(current.remaining_quantity, policy.fee_per_share),
                activation_sha256=activation.semantic_sha256,
                dispatch_sha256=dispatch.semantic_sha256,
            )
        )
    payload = ActivateRuntimeCommitments(
        account_id=state.account_id,
        source_state_sha256=state.semantic_sha256,
        source_snapshot_sha256=snapshot.semantic_sha256,
        original_policy_sha256=policy.semantic_sha256,
        decision_sha256=decision.semantic_sha256,
        evidence_sha256=evidence.semantic_sha256,
        checked_at=first.checked_at,
        expires_at=min(item.activation.expires_at for item in dispatches),
        terms=tuple(sorted(terms, key=lambda item: item.commitment_id)),
    )
    command = AccountingCommand(
        canonical_id("runtime-activate-batch", payload.semantic_sha256), payload
    )
    transition = accounting.advance(
        state=state, command=command, context=context, policy=execution_policy
    )
    if transition.disposition != "applied" or transition.reasons:
        raise ValueError("canonical runtime activation rejected: " + ",".join(transition.reasons))
    if (
        transition.state.submissions != state.submissions
        or transition.state.broker_events != state.broker_events
        or transition.state.cancel_requests != state.cancel_requests
        or transition.state.settlement_instructions != state.settlement_instructions
        or transition.state.settlement_confirmations != state.settlement_confirmations
        or transition.journal_entries
        or transition.due_events
    ):
        raise ValueError("runtime activation unexpectedly changed observed financial facts")
    by_commitment = {c.commitment_id: c for c in transition.state.commitments}
    return PreparedDailyRuntimeActivation(
        command, transition, tuple(by_commitment[term.commitment_id] for term in payload.terms)
    )
