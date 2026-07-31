"""One-shot application orchestration for scheduled Alpaca paper UNKNOWN lookup.

The durable schedule owns trusted-time evaluation and consumes a selected slot
before this workflow invokes the already-restricted Phase 4I lookup runtime.
The workflow never resolves the submission, releases its reservation, retries
an issued ticket, or converts historical lookup evidence into trading
authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, cast

from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    AlpacaPaperAuthenticatedLookupReceipt,
)
from packages.domain.account_coordinator import AccountFence
from packages.domain.unknown_submission_recovery import (
    RecoveryScheduleOutcome,
    UnknownSubmissionRecoveryEvaluation,
    UnknownSubmissionRecoveryPlan,
    UnknownSubmissionRecoveryTicket,
    evaluate_unknown_submission_recovery,
)


class AlpacaPaperUnknownRecoveryError(RuntimeError):
    """Phase 4J application orchestration failed closed."""


class AlpacaPaperUnknownRecoveryScheduleError(AlpacaPaperUnknownRecoveryError):
    """The durable schedule returned evidence for another recovery decision."""


class AlpacaPaperUnknownRecoveryExecutionError(AlpacaPaperUnknownRecoveryError):
    """One consumed recovery ticket did not produce attachable lookup evidence."""


class AlpacaPaperUnknownRecoveryScheduleState(StrEnum):
    """Application-level projection of every durable schedule decision."""

    WAITING = "waiting"
    DUE = "due"
    ACTIVE = "active"
    EXHAUSTED = "exhausted"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    BLOCKED_MISMATCH = "blocked_mismatch"


class AlpacaPaperUnknownRecoveryClaimPort(Protocol):
    """Structurally expose one already-durable, bounded schedule claim."""

    @property
    def ticket(self) -> UnknownSubmissionRecoveryTicket: ...

    @property
    def issued_at(self) -> datetime: ...

    @property
    def valid_until(self) -> datetime: ...


class AlpacaPaperUnknownRecoveryDecisionPort(Protocol):
    """Structurally expose a durable schedule evaluation without persistence imports."""

    @property
    def outcome(self) -> StrEnum: ...

    @property
    def evaluation(self) -> UnknownSubmissionRecoveryEvaluation: ...

    @property
    def claim(self) -> AlpacaPaperUnknownRecoveryClaimPort | None: ...

    @property
    def newly_issued(self) -> bool: ...


class AlpacaPaperUnknownRecoverySchedulePort(Protocol):
    """Durably decide one poll, consume a due claim, and attach its observation."""

    def evaluate(
        self,
        plan: UnknownSubmissionRecoveryPlan,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperUnknownRecoveryDecisionPort: ...

    def record_observation(
        self,
        *,
        plan_id: str,
        claim: AlpacaPaperUnknownRecoveryClaimPort,
        receipt: AlpacaPaperAuthenticatedLookupReceipt,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedLookupReceipt: ...


class AlpacaPaperUnknownLookupExecutor(Protocol):
    """Execute Phase 4I using only identities derived by a durable ticket."""

    def execute(
        self,
        *,
        request_idempotency_key: str,
        delivery_idempotency_key: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt: ...


@dataclass(frozen=True, slots=True)
class AlpacaPaperUnknownRecoveryResult:
    """Ephemeral result from one bounded poll; never recovery authority."""

    schedule_state: AlpacaPaperUnknownRecoveryScheduleState
    evaluation: UnknownSubmissionRecoveryEvaluation
    newly_issued: bool
    lookup_receipt: AlpacaPaperAuthenticatedLookupReceipt | None

    def __post_init__(self) -> None:
        if type(self.schedule_state) is not AlpacaPaperUnknownRecoveryScheduleState:
            raise AlpacaPaperUnknownRecoveryScheduleError(
                "UNKNOWN recovery result requires an exact application schedule state"
            )
        if type(self.evaluation) is not UnknownSubmissionRecoveryEvaluation:
            raise AlpacaPaperUnknownRecoveryScheduleError(
                "UNKNOWN recovery result requires an exact schedule evaluation"
            )
        if type(self.newly_issued) is not bool:
            raise AlpacaPaperUnknownRecoveryScheduleError(
                "UNKNOWN recovery result newly_issued flag must be exact"
            )
        _require_result_state_combination(
            schedule_state=self.schedule_state,
            evaluation=self.evaluation,
            newly_issued=self.newly_issued,
        )
        if self.newly_issued:
            if type(self.lookup_receipt) is not AlpacaPaperAuthenticatedLookupReceipt:
                raise AlpacaPaperUnknownRecoveryExecutionError(
                    "due UNKNOWN recovery result requires an exact lookup receipt"
                )
        elif self.lookup_receipt is not None:
            raise AlpacaPaperUnknownRecoveryScheduleError(
                "non-issued UNKNOWN recovery result cannot carry a lookup receipt"
            )

    @property
    def lookup_executed(self) -> bool:
        return self.lookup_receipt is not None

    @property
    def terminal(self) -> bool:
        return self.schedule_state in {
            AlpacaPaperUnknownRecoveryScheduleState.EXHAUSTED,
            AlpacaPaperUnknownRecoveryScheduleState.RECONCILIATION_REQUIRED,
            AlpacaPaperUnknownRecoveryScheduleState.BLOCKED_MISMATCH,
        }

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _require_exact_registered_evaluation(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    evaluation: object,
) -> UnknownSubmissionRecoveryEvaluation:
    if type(evaluation) is not UnknownSubmissionRecoveryEvaluation:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "durable UNKNOWN recovery schedule returned an invalid evaluation"
        )
    evaluation._validate()
    expected = evaluate_unknown_submission_recovery(
        plan=plan,
        evaluated_at=evaluation.evaluated_at,
        consumed_slot_ids=evaluation.consumed_slot_ids,
    )
    if evaluation != expected:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "durable UNKNOWN recovery evaluation conflicts with the exact plan"
        )
    return evaluation


def _require_utc(value: object, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise AlpacaPaperUnknownRecoveryScheduleError(f"{field_name} must be exact UTC")
    return value


def _normalize_schedule_state(value: object) -> AlpacaPaperUnknownRecoveryScheduleState:
    if not isinstance(value, StrEnum):
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "durable UNKNOWN recovery decision outcome must be an exact string enum"
        )
    try:
        return AlpacaPaperUnknownRecoveryScheduleState(value.value)
    except ValueError:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "durable UNKNOWN recovery decision outcome is unsupported"
        ) from None


def _require_result_state_combination(
    *,
    schedule_state: AlpacaPaperUnknownRecoveryScheduleState,
    evaluation: UnknownSubmissionRecoveryEvaluation,
    newly_issued: bool,
) -> None:
    if schedule_state is AlpacaPaperUnknownRecoveryScheduleState.DUE:
        if not newly_issued or evaluation.outcome is not RecoveryScheduleOutcome.DUE:
            raise AlpacaPaperUnknownRecoveryScheduleError(
                "due UNKNOWN recovery state requires one newly issued due evaluation"
            )
        return
    if newly_issued:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "only the due UNKNOWN recovery state can be newly issued"
        )
    if (
        schedule_state is AlpacaPaperUnknownRecoveryScheduleState.WAITING
        and evaluation.outcome is not RecoveryScheduleOutcome.WAITING
    ):
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "waiting UNKNOWN recovery state requires a waiting evaluation"
        )
    if (
        schedule_state is AlpacaPaperUnknownRecoveryScheduleState.ACTIVE
        and evaluation.outcome is RecoveryScheduleOutcome.EXHAUSTED
    ):
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "active UNKNOWN recovery state cannot outlive the recovery deadline"
        )
    if (
        schedule_state is AlpacaPaperUnknownRecoveryScheduleState.EXHAUSTED
        and evaluation.outcome is not RecoveryScheduleOutcome.EXHAUSTED
    ):
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "exhausted UNKNOWN recovery state requires an exhausted evaluation"
        )


def _require_schedule_decision(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    decision: object,
) -> tuple[
    AlpacaPaperUnknownRecoveryScheduleState,
    UnknownSubmissionRecoveryEvaluation,
    AlpacaPaperUnknownRecoveryClaimPort | None,
    bool,
]:
    structural_decision = cast(AlpacaPaperUnknownRecoveryDecisionPort, decision)
    try:
        raw_outcome = structural_decision.outcome
        raw_evaluation = structural_decision.evaluation
        raw_claim = structural_decision.claim
        newly_issued = structural_decision.newly_issued
    except AttributeError:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "durable UNKNOWN recovery schedule returned an invalid decision"
        ) from None
    if type(newly_issued) is not bool:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "durable UNKNOWN recovery decision newly_issued flag must be exact"
        )
    schedule_state = _normalize_schedule_state(raw_outcome)
    evaluation = _require_exact_registered_evaluation(
        plan=plan,
        evaluation=raw_evaluation,
    )
    if raw_claim is None:
        if newly_issued:
            raise AlpacaPaperUnknownRecoveryScheduleError(
                "newly issued UNKNOWN recovery decision lacks a durable claim"
            )
        if schedule_state in {
            AlpacaPaperUnknownRecoveryScheduleState.DUE,
            AlpacaPaperUnknownRecoveryScheduleState.ACTIVE,
        }:
            raise AlpacaPaperUnknownRecoveryScheduleError(
                "due or active UNKNOWN recovery state lacks a durable claim"
            )
        _require_result_state_combination(
            schedule_state=schedule_state,
            evaluation=evaluation,
            newly_issued=False,
        )
        return schedule_state, evaluation, None, False

    claim = raw_claim
    try:
        ticket = claim.ticket
        issued_at = _require_utc(claim.issued_at, "UNKNOWN recovery claim issued_at")
        valid_until = _require_utc(
            claim.valid_until,
            "UNKNOWN recovery claim valid_until",
        )
    except AttributeError:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "durable UNKNOWN recovery schedule returned an invalid claim"
        ) from None
    if type(ticket) is not UnknownSubmissionRecoveryTicket:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "durable UNKNOWN recovery claim lacks an exact ticket"
        )
    if schedule_state not in {
        AlpacaPaperUnknownRecoveryScheduleState.DUE,
        AlpacaPaperUnknownRecoveryScheduleState.ACTIVE,
    }:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "only due or active UNKNOWN recovery state may carry a claim"
        )
    selected_ticket = evaluation.selected_ticket
    if (
        ticket.plan_id != plan.plan_id
        or ticket.plan_sha256 != plan.semantic_sha256
        or not ticket.scheduled_at <= issued_at < valid_until
        or valid_until > ticket.recovery_deadline_at
    ):
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "durable UNKNOWN recovery claim conflicts with the exact evaluation"
        )
    if newly_issued:
        if (
            schedule_state is not AlpacaPaperUnknownRecoveryScheduleState.DUE
            or evaluation.outcome is not RecoveryScheduleOutcome.DUE
            or selected_ticket is None
            or ticket != selected_ticket
            or issued_at != evaluation.evaluated_at
        ):
            raise AlpacaPaperUnknownRecoveryScheduleError(
                "newly issued UNKNOWN recovery claim conflicts with the due evaluation"
            )
    else:
        if schedule_state is not AlpacaPaperUnknownRecoveryScheduleState.ACTIVE:
            raise AlpacaPaperUnknownRecoveryScheduleError(
                "a retained UNKNOWN recovery claim requires active schedule state"
            )
        if not issued_at <= evaluation.evaluated_at < valid_until:
            raise AlpacaPaperUnknownRecoveryScheduleError(
                "retained UNKNOWN recovery claim is not active at evaluation"
            )
    _require_result_state_combination(
        schedule_state=schedule_state,
        evaluation=evaluation,
        newly_issued=newly_issued,
    )
    return schedule_state, evaluation, claim, newly_issued


def _receipt_matches_ticket(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    claim: AlpacaPaperUnknownRecoveryClaimPort,
    ticket: UnknownSubmissionRecoveryTicket,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
    fence: AccountFence,
) -> bool:
    """Check only application-visible pins; the durable recorder reauthenticates all."""

    return (
        receipt.account_id == ticket.account_id == plan.account_id
        and receipt.attempt_id == ticket.attempt_id == plan.attempt_id
        and receipt.attempt_sha256 == plan.attempt_sha256
        and receipt.terminal_event_id == plan.unknown_event_id
        and receipt.terminal_event_sha256 == plan.unknown_event_sha256
        and receipt.terminal_event_sequence == plan.unknown_sequence_number
        and receipt.client_order_id == plan.client_order_id
        and receipt.demand_id == ticket.demand_id
        and receipt.ingress_receipt_id == ticket.delivery_id
        and receipt.fence_owner_id == fence.owner_id
        and receipt.fence_lease_id == fence.lease_id
        and receipt.fence_fencing_generation == fence.fencing_generation
        and claim.issued_at <= receipt.requested_at < claim.valid_until
    )


def run_alpaca_paper_unknown_recovery_once(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    schedule: AlpacaPaperUnknownRecoverySchedulePort,
    executor: AlpacaPaperUnknownLookupExecutor,
    fence: AccountFence,
) -> AlpacaPaperUnknownRecoveryResult:
    """Evaluate one durable slot and execute at most one scheduled Phase 4I lookup.

    A due ticket is durably consumed before the executor is called.  Any
    executor failure therefore burns that identity and is deliberately reported
    without its original diagnostic text or exception chain.
    """

    if type(plan) is not UnknownSubmissionRecoveryPlan:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "UNKNOWN recovery workflow requires an exact recovery plan"
        )
    plan._validate()
    if type(fence) is not AccountFence:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "UNKNOWN recovery workflow requires an exact account fence"
        )
    fence.__post_init__()
    if fence.account_id != plan.account_id:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "UNKNOWN recovery fence belongs to another account"
        )
    schedule_state, evaluation, claim, newly_issued = _require_schedule_decision(
        plan=plan,
        decision=schedule.evaluate(plan, fence=fence),
    )
    if not newly_issued:
        return AlpacaPaperUnknownRecoveryResult(
            schedule_state=schedule_state,
            evaluation=evaluation,
            newly_issued=False,
            lookup_receipt=None,
        )

    if claim is None or type(claim.ticket) is not UnknownSubmissionRecoveryTicket:
        raise AlpacaPaperUnknownRecoveryScheduleError(
            "due UNKNOWN recovery evaluation lacks an exact durable ticket"
        )
    ticket = claim.ticket
    try:
        receipt = executor.execute(
            request_idempotency_key=ticket.demand_idempotency_key,
            delivery_idempotency_key=ticket.delivery_idempotency_key,
        )
        if type(receipt) is not AlpacaPaperAuthenticatedLookupReceipt:
            raise TypeError("lookup executor returned another receipt type")
        receipt._validate()
        if not _receipt_matches_ticket(
            plan=plan,
            claim=claim,
            ticket=ticket,
            receipt=receipt,
            fence=fence,
        ):
            raise ValueError("lookup receipt conflicts with its recovery ticket")
    except Exception:
        raise AlpacaPaperUnknownRecoveryExecutionError(
            "scheduled UNKNOWN lookup failed after durable ticket consumption"
        ) from None

    try:
        acknowledged_receipt = schedule.record_observation(
            plan_id=plan.plan_id,
            claim=claim,
            receipt=receipt,
            fence=fence,
        )
        if type(acknowledged_receipt) is not AlpacaPaperAuthenticatedLookupReceipt:
            raise TypeError("recovery recorder returned another acknowledgement type")
        acknowledged_receipt._validate()
        if (
            acknowledged_receipt.receipt_id != receipt.receipt_id
            or acknowledged_receipt.semantic_sha256 != receipt.semantic_sha256
            or acknowledged_receipt != receipt
        ):
            raise ValueError("recovery recorder acknowledged different lookup evidence")
    except Exception:
        raise AlpacaPaperUnknownRecoveryExecutionError(
            "scheduled UNKNOWN lookup was not durably acknowledged"
        ) from None
    return AlpacaPaperUnknownRecoveryResult(
        schedule_state=schedule_state,
        evaluation=evaluation,
        newly_issued=True,
        lookup_receipt=receipt,
    )


__all__ = [
    "AlpacaPaperUnknownLookupExecutor",
    "AlpacaPaperUnknownRecoveryClaimPort",
    "AlpacaPaperUnknownRecoveryDecisionPort",
    "AlpacaPaperUnknownRecoveryError",
    "AlpacaPaperUnknownRecoveryExecutionError",
    "AlpacaPaperUnknownRecoveryResult",
    "AlpacaPaperUnknownRecoveryScheduleError",
    "AlpacaPaperUnknownRecoverySchedulePort",
    "AlpacaPaperUnknownRecoveryScheduleState",
    "run_alpaca_paper_unknown_recovery_once",
]
