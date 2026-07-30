from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    AlpacaPaperAuthenticatedLookupReceipt,
    _observe_authenticated_alpaca_paper_unknown_lookup_with_transport,
    alpaca_paper_unknown_lookup_correlation_sha256,
)
from packages.application.alpaca_paper_unknown_recovery import (
    AlpacaPaperUnknownLookupExecutor,
    AlpacaPaperUnknownRecoveryClaimPort,
    AlpacaPaperUnknownRecoveryDecisionPort,
    AlpacaPaperUnknownRecoveryExecutionError,
    AlpacaPaperUnknownRecoveryScheduleError,
    AlpacaPaperUnknownRecoveryScheduleState,
    run_alpaca_paper_unknown_recovery_once,
)
from packages.domain.account_coordinator import AccountFence
from packages.domain.unknown_submission_recovery import (
    RecoveryScheduleOutcome,
    UnknownSubmissionRecoveryEvaluation,
    UnknownSubmissionRecoveryPlan,
    UnknownSubmissionRecoveryTicket,
    create_unknown_submission_recovery_plan,
    evaluate_unknown_submission_recovery,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    InMemoryBudget,
    SequenceClock,
)
from tests.unit.test_alpaca_paper_lookup_runtime import (
    FixedCoordinator,
    LookupScenario,
    _scenario,
)
from tests.unit.test_submission_attempt import fence_receipt
from tests.unit.test_unknown_submission_recovery import (
    DISPATCH_AT as RECOVERY_DISPATCH_AT,
)
from tests.unit.test_unknown_submission_recovery import plan as recovery_plan_fixture

LOOKUP_AT = datetime(2026, 7, 15, 13, 32, 1, tzinfo=UTC)
_DEFAULT_RECORD_ACK = object()


@dataclass(frozen=True, slots=True)
class Claim:
    ticket: UnknownSubmissionRecoveryTicket
    issued_at: datetime
    valid_until: datetime


@dataclass(frozen=True, slots=True)
class Decision:
    outcome: AlpacaPaperUnknownRecoveryScheduleState
    evaluation: UnknownSubmissionRecoveryEvaluation
    claim: Claim | None
    newly_issued: bool


class Schedule:
    def __init__(
        self,
        decision: Decision,
        *,
        events: list[str],
        record_error: Exception | None = None,
        record_ack: object = _DEFAULT_RECORD_ACK,
    ) -> None:
        self.decision = decision
        self.events = events
        self.record_error = record_error
        self.record_ack = record_ack
        self.evaluate_calls: list[tuple[UnknownSubmissionRecoveryPlan, AccountFence]] = []
        self.record_calls: list[
            tuple[str, Claim, AlpacaPaperAuthenticatedLookupReceipt, AccountFence]
        ] = []
        self.consumed_ticket_ids: list[str] = []

    def evaluate(
        self,
        plan: UnknownSubmissionRecoveryPlan,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperUnknownRecoveryDecisionPort:
        self.events.append("evaluate")
        self.evaluate_calls.append((plan, fence))
        if self.decision.newly_issued and self.decision.claim is not None:
            self.consumed_ticket_ids.append(self.decision.claim.ticket.ticket_id)
        return self.decision

    def record_observation(
        self,
        *,
        plan_id: str,
        claim: AlpacaPaperUnknownRecoveryClaimPort,
        receipt: AlpacaPaperAuthenticatedLookupReceipt,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        self.events.append("record")
        self.record_calls.append((plan_id, cast(Claim, claim), receipt, fence))
        if self.record_error is not None:
            raise self.record_error
        if self.record_ack is _DEFAULT_RECORD_ACK:
            return receipt
        return cast(AlpacaPaperAuthenticatedLookupReceipt, self.record_ack)


class NeverExecutor:
    def execute(
        self,
        *,
        request_idempotency_key: str,
        delivery_idempotency_key: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        del request_idempotency_key, delivery_idempotency_key
        raise AssertionError("non-issued schedule decision performed broker I/O")


class RaisingExecutor:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls: list[tuple[str, str]] = []

    def execute(
        self,
        *,
        request_idempotency_key: str,
        delivery_idempotency_key: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        self.events.append("execute")
        self.calls.append((request_idempotency_key, delivery_idempotency_key))
        raise RuntimeError("unsafe provider diagnostic paper-secret-must-not-leak")


class RuntimeExecutor:
    def __init__(
        self,
        *,
        scenario: LookupScenario,
        fence: AccountFence,
        events: list[str],
    ) -> None:
        self.scenario = scenario
        self.fence = fence
        self.events = events
        self.calls: list[tuple[str, str]] = []

    def execute(
        self,
        *,
        request_idempotency_key: str,
        delivery_idempotency_key: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        self.events.append("execute")
        self.calls.append((request_idempotency_key, delivery_idempotency_key))
        scenario = self.scenario
        return _observe_authenticated_alpaca_paper_unknown_lookup_with_transport(
            security_reference=scenario.security_reference,
            account_binding=scenario.account_binding,
            attempt=scenario.attempt,
            description=scenario.description,
            credential_resolver=scenario.resolver,
            transport=scenario.transport,
            budget=scenario.budget,  # type: ignore[arg-type]
            unknown_attempts=scenario.unknown_attempts,
            account_bindings=scenario.account_bindings,  # type: ignore[arg-type]
            coordinator=scenario.coordinator,  # type: ignore[arg-type]
            fence=self.fence,
            ingress_recorder=scenario.ingress,
            lookup_recorder=scenario.lookups,
            clock=scenario.clock,
            request_idempotency_key=request_idempotency_key,
            delivery_idempotency_key=delivery_idempotency_key,
        )


@dataclass(frozen=True, slots=True)
class PreparedDue:
    scenario: LookupScenario
    plan: UnknownSubmissionRecoveryPlan
    evaluation: UnknownSubmissionRecoveryEvaluation
    claim: Claim
    fence: AccountFence


def _lookup_clock() -> SequenceClock:
    return SequenceClock(
        LOOKUP_AT,
        LOOKUP_AT + timedelta(milliseconds=50),
        LOOKUP_AT + timedelta(milliseconds=100),
        LOOKUP_AT + timedelta(milliseconds=500),
        LOOKUP_AT + timedelta(milliseconds=600),
        LOOKUP_AT + timedelta(milliseconds=700),
        LOOKUP_AT + timedelta(milliseconds=800),
        LOOKUP_AT + timedelta(milliseconds=900),
        LOOKUP_AT + timedelta(milliseconds=1100),
        LOOKUP_AT + timedelta(milliseconds=1200),
    )


def prepared_due() -> PreparedDue:
    scenario = _scenario(
        budget=InMemoryBudget(
            issued_at=LOOKUP_AT + timedelta(milliseconds=200),
            checked_at=LOOKUP_AT + timedelta(milliseconds=400),
        ),
        coordinator=FixedCoordinator(
            pre_validated_at=LOOKUP_AT + timedelta(milliseconds=300),
            post_validated_at=LOOKUP_AT + timedelta(seconds=1),
            pre_valid_until=LOOKUP_AT + timedelta(seconds=5),
            post_valid_until=LOOKUP_AT + timedelta(seconds=5),
        ),
        clock=_lookup_clock(),
    )
    correlation_sha256 = alpaca_paper_unknown_lookup_correlation_sha256(
        security_reference=scenario.security_reference,
        account_binding=scenario.account_binding,
        attempt=scenario.attempt,
        description=scenario.description,
    )
    recovery_plan = create_unknown_submission_recovery_plan(
        account_id=scenario.attempt.preparation.account_id,
        client_order_id=scenario.description.submission.request.client_order_id,
        attempt_sha256=scenario.attempt.semantic_sha256,
        in_flight_event=scenario.attempt.events[1],
        unknown_event=scenario.attempt.events[2],
        lookup_correlation_sha256=correlation_sha256,
    )
    evaluation = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=LOOKUP_AT,
    )
    assert evaluation.outcome is RecoveryScheduleOutcome.DUE
    assert evaluation.selected_ticket is not None
    claim = Claim(
        ticket=evaluation.selected_ticket,
        issued_at=LOOKUP_AT,
        valid_until=LOOKUP_AT + timedelta(seconds=3),
    )
    return PreparedDue(
        scenario=scenario,
        plan=recovery_plan,
        evaluation=evaluation,
        claim=claim,
        fence=fence_receipt(
            validated_at=LOOKUP_AT - timedelta(seconds=1),
            valid_until=LOOKUP_AT + timedelta(seconds=30),
        ).fence,
    )


def test_new_due_claim_executes_once_after_consumption_then_records_exact_observation() -> None:
    prepared = prepared_due()
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=AlpacaPaperUnknownRecoveryScheduleState.DUE,
            evaluation=prepared.evaluation,
            claim=prepared.claim,
            newly_issued=True,
        ),
        events=events,
    )
    executor = RuntimeExecutor(
        scenario=prepared.scenario,
        fence=prepared.fence,
        events=events,
    )

    result = run_alpaca_paper_unknown_recovery_once(
        plan=prepared.plan,
        schedule=schedule,
        executor=executor,
        fence=prepared.fence,
    )

    ticket = prepared.claim.ticket
    assert events == ["evaluate", "execute", "record"]
    assert schedule.consumed_ticket_ids == [ticket.ticket_id]
    assert executor.calls == [
        (
            ticket.demand_idempotency_key,
            ticket.delivery_idempotency_key,
        )
    ]
    assert len(schedule.record_calls) == 1
    plan_id, recorded_claim, recorded_receipt, recorded_fence = schedule.record_calls[0]
    assert plan_id == prepared.plan.plan_id
    assert recorded_claim is prepared.claim
    assert recorded_receipt is result.lookup_receipt
    assert recorded_fence is prepared.fence
    assert schedule.evaluate_calls == [(prepared.plan, prepared.fence)]
    assert result.schedule_state is AlpacaPaperUnknownRecoveryScheduleState.DUE
    assert result.evaluation is prepared.evaluation
    assert result.newly_issued is True
    assert result.lookup_executed is True
    assert result.terminal is False
    assert result.transport_authorized is False
    assert result.unknown_resolution_authorized is False
    assert result.reservation_release_authorized is False
    assert result.lifecycle_application_authorized is False
    assert result.resubmission_authorized is False
    assert result.trading_effect_authorized is False


@pytest.mark.parametrize("exhausted", [False, True])
def test_waiting_and_exhausted_decisions_perform_no_lookup_or_observation(
    exhausted: bool,
) -> None:
    prepared = prepared_due()
    evaluated_at = (
        prepared.plan.recovery_deadline_at if exhausted else prepared.plan.unknown_recorded_at
    )
    evaluation = evaluate_unknown_submission_recovery(
        plan=prepared.plan,
        evaluated_at=evaluated_at,
    )
    expected_outcome = (
        RecoveryScheduleOutcome.EXHAUSTED if exhausted else RecoveryScheduleOutcome.WAITING
    )
    assert evaluation.outcome is expected_outcome
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=(
                AlpacaPaperUnknownRecoveryScheduleState.EXHAUSTED
                if exhausted
                else AlpacaPaperUnknownRecoveryScheduleState.WAITING
            ),
            evaluation=evaluation,
            claim=None,
            newly_issued=False,
        ),
        events=events,
    )

    result = run_alpaca_paper_unknown_recovery_once(
        plan=prepared.plan,
        schedule=schedule,
        executor=NeverExecutor(),
        fence=prepared.fence,
    )

    assert events == ["evaluate"]
    assert schedule.record_calls == []
    assert result.schedule_state is (
        AlpacaPaperUnknownRecoveryScheduleState.EXHAUSTED
        if exhausted
        else AlpacaPaperUnknownRecoveryScheduleState.WAITING
    )
    assert result.evaluation is evaluation
    assert result.newly_issued is False
    assert result.lookup_receipt is None
    assert result.lookup_executed is False
    assert result.terminal is exhausted
    assert result.unknown_resolution_authorized is False
    assert result.resubmission_authorized is False


@pytest.mark.parametrize(
    "schedule_state",
    [
        AlpacaPaperUnknownRecoveryScheduleState.RECONCILIATION_REQUIRED,
        AlpacaPaperUnknownRecoveryScheduleState.BLOCKED_MISMATCH,
    ],
)
def test_terminal_observation_state_remains_visible_when_pure_evaluation_is_due(
    schedule_state: AlpacaPaperUnknownRecoveryScheduleState,
) -> None:
    prepared = prepared_due()
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=schedule_state,
            evaluation=prepared.evaluation,
            claim=None,
            newly_issued=False,
        ),
        events=events,
    )

    result = run_alpaca_paper_unknown_recovery_once(
        plan=prepared.plan,
        schedule=schedule,
        executor=NeverExecutor(),
        fence=prepared.fence,
    )

    assert events == ["evaluate"]
    assert result.schedule_state is schedule_state
    assert result.evaluation.outcome is RecoveryScheduleOutcome.DUE
    assert result.newly_issued is False
    assert result.lookup_executed is False
    assert result.terminal is True


@pytest.mark.parametrize(
    ("schedule_state", "evaluated_at", "expected_outcome"),
    [
        (
            AlpacaPaperUnknownRecoveryScheduleState.WAITING,
            RECOVERY_DISPATCH_AT + timedelta(seconds=59),
            RecoveryScheduleOutcome.WAITING,
        ),
        (
            AlpacaPaperUnknownRecoveryScheduleState.EXHAUSTED,
            RECOVERY_DISPATCH_AT + timedelta(seconds=60),
            RecoveryScheduleOutcome.EXHAUSTED,
        ),
        (
            AlpacaPaperUnknownRecoveryScheduleState.EXHAUSTED,
            RECOVERY_DISPATCH_AT + timedelta(seconds=61),
            RecoveryScheduleOutcome.EXHAUSTED,
        ),
    ],
)
def test_zero_slot_schedule_never_performs_lookup_before_at_or_after_deadline(
    schedule_state: AlpacaPaperUnknownRecoveryScheduleState,
    evaluated_at: datetime,
    expected_outcome: RecoveryScheduleOutcome,
) -> None:
    recovery_plan = recovery_plan_fixture(
        unknown_recorded_at=RECOVERY_DISPATCH_AT + timedelta(seconds=59)
    )
    assert recovery_plan.slots == ()
    evaluation = evaluate_unknown_submission_recovery(
        plan=recovery_plan,
        evaluated_at=evaluated_at,
    )
    assert evaluation.outcome is expected_outcome
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=schedule_state,
            evaluation=evaluation,
            claim=None,
            newly_issued=False,
        ),
        events=events,
    )
    fence = AccountFence(
        account_id=recovery_plan.account_id,
        owner_id="zero-slot-worker",
        lease_id="zero-slot-lease",
        fencing_generation=1,
    )

    result = run_alpaca_paper_unknown_recovery_once(
        plan=recovery_plan,
        schedule=schedule,
        executor=NeverExecutor(),
        fence=fence,
    )

    assert events == ["evaluate"]
    assert result.schedule_state is schedule_state
    assert result.lookup_executed is False


@pytest.mark.parametrize(
    ("schedule_state", "claim", "newly_issued", "message"),
    [
        (
            AlpacaPaperUnknownRecoveryScheduleState.WAITING,
            None,
            False,
            "waiting",
        ),
        (
            AlpacaPaperUnknownRecoveryScheduleState.DUE,
            None,
            True,
            "lacks a durable claim",
        ),
        (
            AlpacaPaperUnknownRecoveryScheduleState.ACTIVE,
            None,
            False,
            "lacks a durable claim",
        ),
    ],
)
def test_invalid_state_claim_and_evaluation_combinations_fail_before_lookup(
    schedule_state: AlpacaPaperUnknownRecoveryScheduleState,
    claim: Claim | None,
    newly_issued: bool,
    message: str,
) -> None:
    prepared = prepared_due()
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=schedule_state,
            evaluation=prepared.evaluation,
            claim=claim,
            newly_issued=newly_issued,
        ),
        events=events,
    )

    with pytest.raises(AlpacaPaperUnknownRecoveryScheduleError, match=message):
        run_alpaca_paper_unknown_recovery_once(
            plan=prepared.plan,
            schedule=schedule,
            executor=NeverExecutor(),
            fence=prepared.fence,
        )

    assert events == ["evaluate"]


def test_active_existing_claim_is_never_redelivered() -> None:
    prepared = prepared_due()
    active_at = prepared.claim.issued_at + timedelta(seconds=1)
    evaluation = evaluate_unknown_submission_recovery(
        plan=prepared.plan,
        evaluated_at=active_at,
    )
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=AlpacaPaperUnknownRecoveryScheduleState.ACTIVE,
            evaluation=evaluation,
            claim=prepared.claim,
            newly_issued=False,
        ),
        events=events,
    )

    result = run_alpaca_paper_unknown_recovery_once(
        plan=prepared.plan,
        schedule=schedule,
        executor=NeverExecutor(),
        fence=prepared.fence,
    )

    assert events == ["evaluate"]
    assert result.schedule_state is AlpacaPaperUnknownRecoveryScheduleState.ACTIVE
    assert result.newly_issued is False
    assert result.lookup_executed is False
    assert schedule.record_calls == []


def test_executor_failure_burns_ticket_and_raises_only_sanitized_error() -> None:
    prepared = prepared_due()
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=AlpacaPaperUnknownRecoveryScheduleState.DUE,
            evaluation=prepared.evaluation,
            claim=prepared.claim,
            newly_issued=True,
        ),
        events=events,
    )
    executor = RaisingExecutor(events)

    with pytest.raises(AlpacaPaperUnknownRecoveryExecutionError) as captured:
        run_alpaca_paper_unknown_recovery_once(
            plan=prepared.plan,
            schedule=schedule,
            executor=executor,
            fence=prepared.fence,
        )

    assert events == ["evaluate", "execute"]
    assert schedule.consumed_ticket_ids == [prepared.claim.ticket.ticket_id]
    assert schedule.record_calls == []
    assert "paper-secret-must-not-leak" not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True


def test_exact_receipt_validation_failure_is_sanitized_and_not_recorded() -> None:
    prepared = prepared_due()
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=AlpacaPaperUnknownRecoveryScheduleState.DUE,
            evaluation=prepared.evaluation,
            claim=prepared.claim,
            newly_issued=True,
        ),
        events=events,
    )
    forged = object.__new__(AlpacaPaperAuthenticatedLookupReceipt)

    class ForgedExecutor:
        def execute(
            self,
            *,
            request_idempotency_key: str,
            delivery_idempotency_key: str,
        ) -> AlpacaPaperAuthenticatedLookupReceipt:
            del request_idempotency_key, delivery_idempotency_key
            events.append("execute")
            return forged

    with pytest.raises(AlpacaPaperUnknownRecoveryExecutionError):
        run_alpaca_paper_unknown_recovery_once(
            plan=prepared.plan,
            schedule=schedule,
            executor=ForgedExecutor(),
            fence=prepared.fence,
        )

    assert events == ["evaluate", "execute"]
    assert schedule.record_calls == []


@pytest.mark.parametrize(
    "record_ack",
    [None, object()],
    ids=["absent", "wrong-type"],
)
def test_missing_or_invalid_observation_acknowledgement_fails_closed(
    record_ack: object,
) -> None:
    prepared = prepared_due()
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=AlpacaPaperUnknownRecoveryScheduleState.DUE,
            evaluation=prepared.evaluation,
            claim=prepared.claim,
            newly_issued=True,
        ),
        events=events,
        record_ack=record_ack,
    )
    executor = RuntimeExecutor(
        scenario=prepared.scenario,
        fence=prepared.fence,
        events=events,
    )

    with pytest.raises(
        AlpacaPaperUnknownRecoveryExecutionError,
        match="not durably acknowledged",
    ) as captured:
        run_alpaca_paper_unknown_recovery_once(
            plan=prepared.plan,
            schedule=schedule,
            executor=executor,
            fence=prepared.fence,
        )

    assert events == ["evaluate", "execute", "record"]
    assert len(schedule.record_calls) == 1
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True


def test_newly_issued_claim_must_match_due_evaluation_before_executor_io() -> None:
    prepared = prepared_due()
    earlier_evaluation = evaluate_unknown_submission_recovery(
        plan=prepared.plan,
        evaluated_at=prepared.plan.slots[0].scheduled_at,
    )
    assert earlier_evaluation.selected_ticket is not None
    mismatched_claim = Claim(
        ticket=earlier_evaluation.selected_ticket,
        issued_at=prepared.evaluation.evaluated_at,
        valid_until=prepared.evaluation.evaluated_at + timedelta(seconds=3),
    )
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=AlpacaPaperUnknownRecoveryScheduleState.DUE,
            evaluation=prepared.evaluation,
            claim=mismatched_claim,
            newly_issued=True,
        ),
        events=events,
    )

    with pytest.raises(AlpacaPaperUnknownRecoveryScheduleError, match="due evaluation"):
        run_alpaca_paper_unknown_recovery_once(
            plan=prepared.plan,
            schedule=schedule,
            executor=NeverExecutor(),
            fence=prepared.fence,
        )

    assert events == ["evaluate"]
    assert schedule.record_calls == []


class FenceLost(RuntimeError):
    pass


def test_schedule_fence_loss_is_propagated_before_executor_io() -> None:
    prepared = prepared_due()
    seen: list[AccountFence] = []

    class LostSchedule:
        def evaluate(
            self,
            plan: UnknownSubmissionRecoveryPlan,
            *,
            fence: AccountFence,
        ) -> AlpacaPaperUnknownRecoveryDecisionPort:
            assert plan is prepared.plan
            seen.append(fence)
            raise FenceLost("current recovery fence was lost")

        def record_observation(
            self,
            *,
            plan_id: str,
            claim: AlpacaPaperUnknownRecoveryClaimPort,
            receipt: AlpacaPaperAuthenticatedLookupReceipt,
            fence: AccountFence,
        ) -> AlpacaPaperAuthenticatedLookupReceipt:
            raise AssertionError((plan_id, claim, receipt, fence))

    with pytest.raises(FenceLost, match="fence was lost"):
        run_alpaca_paper_unknown_recovery_once(
            plan=prepared.plan,
            schedule=LostSchedule(),
            executor=NeverExecutor(),
            fence=prepared.fence,
        )

    assert seen == [prepared.fence]


def test_wrong_account_fence_is_rejected_before_schedule_or_executor_io() -> None:
    prepared = prepared_due()
    wrong_fence = AccountFence(
        account_id="another-account",
        owner_id=prepared.fence.owner_id,
        lease_id=prepared.fence.lease_id,
        fencing_generation=prepared.fence.fencing_generation,
    )
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=AlpacaPaperUnknownRecoveryScheduleState.DUE,
            evaluation=prepared.evaluation,
            claim=prepared.claim,
            newly_issued=True,
        ),
        events=events,
    )

    with pytest.raises(AlpacaPaperUnknownRecoveryScheduleError, match="another account"):
        run_alpaca_paper_unknown_recovery_once(
            plan=prepared.plan,
            schedule=schedule,
            executor=NeverExecutor(),
            fence=wrong_fence,
        )

    assert events == []


def test_record_failure_is_sanitized_after_exact_lookup() -> None:
    prepared = prepared_due()
    events: list[str] = []
    schedule = Schedule(
        Decision(
            outcome=AlpacaPaperUnknownRecoveryScheduleState.DUE,
            evaluation=prepared.evaluation,
            claim=prepared.claim,
            newly_issued=True,
        ),
        events=events,
        record_error=FenceLost("current recovery fence was lost secret-recorder-diagnostic"),
    )
    executor = RuntimeExecutor(
        scenario=prepared.scenario,
        fence=prepared.fence,
        events=events,
    )

    with pytest.raises(
        AlpacaPaperUnknownRecoveryExecutionError,
        match="not durably acknowledged",
    ) as captured:
        run_alpaca_paper_unknown_recovery_once(
            plan=prepared.plan,
            schedule=schedule,
            executor=cast(AlpacaPaperUnknownLookupExecutor, executor),
            fence=prepared.fence,
        )

    assert events == ["evaluate", "execute", "record"]
    assert len(schedule.record_calls) == 1
    assert schedule.record_calls[0][3] is prepared.fence
    assert schedule.consumed_ticket_ids == [prepared.claim.ticket.ticket_id]
    assert "secret-recorder-diagnostic" not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
