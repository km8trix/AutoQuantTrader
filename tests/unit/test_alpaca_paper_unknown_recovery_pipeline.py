from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest

from packages.adapters.broker.alpaca_paper_inbox import (
    create_alpaca_paper_inbox_admission_request,
)
from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    AlpacaPaperAuthenticatedLookupReceipt,
)
from packages.adapters.broker.alpaca_paper_reconciliation import (
    normalize_authenticated_alpaca_paper_lookup,
)
from packages.application.alpaca_paper_unknown_recovery import (
    AlpacaPaperUnknownRecoveryClaimPort,
    AlpacaPaperUnknownRecoveryDecisionPort,
    AlpacaPaperUnknownRecoveryScheduleState,
)
from packages.application.alpaca_paper_unknown_recovery_pipeline import (
    AlpacaPaperUnknownRecoveryAccountedObservation,
    AlpacaPaperUnknownRecoveryPipelineConflict,
    AlpacaPaperUnknownRecoveryPipelineExecutionError,
    AlpacaPaperUnknownRecoveryPipelineResult,
    run_alpaca_paper_unknown_recovery_pipeline_once,
)
from packages.domain.account_coordinator import AccountFence
from packages.domain.broker_inbox import (
    BrokerInboxAdmissionRequest,
    BrokerInboxNonApplicationDecisionReceipt,
    decide_broker_inbox_admission,
)
from packages.domain.broker_ingress import BrokerIngressReceipt
from packages.domain.broker_reconciliation import (
    BrokerReconciliationEvidence,
    BrokerReconciliationFact,
    _broker_reconciliation_fact,
)
from packages.domain.submission_attempt import CanonicalSubmissionAttempt
from packages.domain.unknown_submission_recovery import (
    UnknownSubmissionRecoveryPlan,
    evaluate_unknown_submission_recovery,
)
from tests.unit.test_alpaca_paper_unknown_recovery import (
    Claim,
    Decision,
    PreparedDue,
    RuntimeExecutor,
    prepared_due,
)

STORE_IDENTITY = 41_041


@dataclass(frozen=True, slots=True)
class DispatchProgress:
    claim: Claim
    lookup_receipt: AlpacaPaperAuthenticatedLookupReceipt | None


@dataclass(frozen=True, slots=True)
class Progress:
    plan: UnknownSubmissionRecoveryPlan
    dispatches: tuple[DispatchProgress, ...]


class Schedule:
    runtime_store_identity = STORE_IDENTITY

    def __init__(
        self,
        *,
        plan: UnknownSubmissionRecoveryPlan,
        decision: Decision,
        registered: bool,
        dispatches: tuple[DispatchProgress, ...] = (),
        events: list[str] | None = None,
    ) -> None:
        self.plan = plan
        self.decision = decision
        self.registered = registered
        self.dispatches = list(dispatches)
        self.events = events if events is not None else []
        self.load_calls = 0
        self.evaluate_calls = 0
        self.record_calls = 0

    def load_progress(self, plan_id: str) -> Progress | None:
        self.events.append("load_progress")
        self.load_calls += 1
        if plan_id != self.plan.plan_id:
            return None
        if not self.registered:
            return None
        return Progress(plan=self.plan, dispatches=tuple(self.dispatches))

    def evaluate(
        self,
        plan: UnknownSubmissionRecoveryPlan,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperUnknownRecoveryDecisionPort:
        del fence
        self.events.append("evaluate")
        self.evaluate_calls += 1
        assert plan == self.plan
        self.registered = True
        if self.decision.newly_issued:
            assert self.decision.claim is not None
            if not any(
                dispatch.claim.ticket.ticket_id == self.decision.claim.ticket.ticket_id
                for dispatch in self.dispatches
            ):
                self.dispatches.append(
                    DispatchProgress(
                        claim=self.decision.claim,
                        lookup_receipt=None,
                    )
                )
        return self.decision

    def record_observation(
        self,
        *,
        plan_id: str,
        claim: AlpacaPaperUnknownRecoveryClaimPort,
        receipt: AlpacaPaperAuthenticatedLookupReceipt,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        del fence
        self.events.append("record_observation")
        self.record_calls += 1
        assert plan_id == self.plan.plan_id
        for position, dispatch in enumerate(self.dispatches):
            if dispatch.claim.ticket.ticket_id != claim.ticket.ticket_id:
                continue
            if dispatch.lookup_receipt not in (None, receipt):
                raise RuntimeError("conflicting observation")
            self.dispatches[position] = DispatchProgress(
                claim=dispatch.claim,
                lookup_receipt=receipt,
            )
            return receipt
        raise RuntimeError("unknown dispatch")


class LookupRepository:
    runtime_store_identity = STORE_IDENTITY

    def __init__(self, *, events: list[str]) -> None:
        self.events = events
        self.by_id: dict[str, AlpacaPaperAuthenticatedLookupReceipt] = {}
        self.by_ingress: dict[str, AlpacaPaperAuthenticatedLookupReceipt] = {}
        self.ingress_load_calls = 0

    def add(self, receipt: AlpacaPaperAuthenticatedLookupReceipt) -> None:
        self.by_id[receipt.receipt_id] = receipt
        self.by_ingress[receipt.ingress_receipt_id] = receipt

    def load(
        self,
        receipt_id: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt | None:
        self.events.append("lookup_load")
        return self.by_id.get(receipt_id)

    def load_by_ingress_receipt_id(
        self,
        ingress_receipt_id: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt | None:
        self.events.append("lookup_by_ingress")
        self.ingress_load_calls += 1
        return self.by_ingress.get(ingress_receipt_id)


class AttemptLoader:
    runtime_store_identity = STORE_IDENTITY

    def __init__(
        self,
        attempt: CanonicalSubmissionAttempt,
        *,
        events: list[str],
    ) -> None:
        self.attempt = attempt
        self.events = events

    def get(self, attempt_id: str) -> CanonicalSubmissionAttempt | None:
        self.events.append("attempt_load")
        return self.attempt if attempt_id == self.attempt.attempt_id else None


class IngressLoader:
    runtime_store_identity = STORE_IDENTITY

    def __init__(self, prepared: PreparedDue, *, events: list[str]) -> None:
        self.prepared = prepared
        self.events = events

    def load(self, receipt_id: str) -> BrokerIngressReceipt | None:
        self.events.append("ingress_load")
        return next(
            (
                receipt
                for receipt in self.prepared.scenario.ingress.receipts
                if receipt.receipt_id == receipt_id
            ),
            None,
        )


class ReconciliationRepository:
    runtime_store_identity = STORE_IDENTITY

    def __init__(self, *, events: list[str]) -> None:
        self.events = events
        self.facts_by_id: dict[str, BrokerReconciliationFact] = {}
        self.facts_by_lookup: dict[str, BrokerReconciliationFact] = {}
        self.facts_by_account: dict[str, list[BrokerReconciliationFact]] = {}
        self.record_calls = 0
        self.raise_on_source_load = False

    def record(
        self,
        evidence: BrokerReconciliationEvidence,
    ) -> BrokerReconciliationFact:
        self.events.append("reconciliation_record")
        self.record_calls += 1
        existing = self.facts_by_lookup.get(evidence.source_lookup_receipt_id)
        if existing is not None:
            assert existing.evidence == evidence
            return existing
        history = self.facts_by_account.setdefault(evidence.account_id, [])
        previous = None if not history else history[-1]
        fact = _broker_reconciliation_fact(
            evidence,
            normalized_at=(evidence.source_committed_at + timedelta(milliseconds=1)),
            account_sequence=len(history) + 1,
            previous_fact_sha256=(None if previous is None else previous.semantic_sha256),
        )
        history.append(fact)
        self.facts_by_id[fact.fact_id] = fact
        self.facts_by_lookup[evidence.source_lookup_receipt_id] = fact
        return fact

    def load(self, fact_id: str) -> BrokerReconciliationFact | None:
        self.events.append("reconciliation_load")
        return self.facts_by_id.get(fact_id)

    def history(self, account_id: str) -> tuple[BrokerReconciliationFact, ...]:
        return tuple(self.facts_by_account.get(account_id, ()))

    def load_by_lookup_receipt_id(
        self,
        lookup_receipt_id: str,
    ) -> BrokerReconciliationFact | None:
        self.events.append("reconciliation_by_lookup")
        if self.raise_on_source_load:
            raise RuntimeError("unsafe-k-secret")
        return self.facts_by_lookup.get(lookup_receipt_id)


class InboxRepository:
    runtime_store_identity = STORE_IDENTITY

    def __init__(self, *, events: list[str]) -> None:
        self.events = events
        self.decisions_by_id: dict[
            str,
            BrokerInboxNonApplicationDecisionReceipt,
        ] = {}
        self.decisions_by_fact: dict[
            str,
            BrokerInboxNonApplicationDecisionReceipt,
        ] = {}
        self.decisions_by_account: dict[
            str,
            list[BrokerInboxNonApplicationDecisionReceipt],
        ] = {}
        self.record_calls = 0

    def record(
        self,
        request: BrokerInboxAdmissionRequest,
    ) -> BrokerInboxNonApplicationDecisionReceipt:
        self.events.append("inbox_record")
        self.record_calls += 1
        fact_id = request.source_fact.fact_id
        existing = self.decisions_by_fact.get(fact_id)
        if existing is not None:
            assert existing.request == request
            return existing
        decision = decide_broker_inbox_admission(
            request,
            decided_at=request.source_fact.normalized_at + timedelta(milliseconds=1),
        )
        self.decisions_by_id[decision.decision_id] = decision
        self.decisions_by_fact[fact_id] = decision
        self.decisions_by_account.setdefault(
            request.identity.account_id,
            [],
        ).append(decision)
        return decision

    def load(
        self,
        decision_id: str,
    ) -> BrokerInboxNonApplicationDecisionReceipt | None:
        self.events.append("inbox_load")
        return self.decisions_by_id.get(decision_id)

    def history(
        self,
        account_id: str,
    ) -> tuple[BrokerInboxNonApplicationDecisionReceipt, ...]:
        return tuple(self.decisions_by_account.get(account_id, ()))

    def load_by_reconciliation_fact_id(
        self,
        reconciliation_fact_id: str,
    ) -> BrokerInboxNonApplicationDecisionReceipt | None:
        self.events.append("inbox_by_reconciliation")
        return self.decisions_by_fact.get(reconciliation_fact_id)


class Executor:
    runtime_store_identity = STORE_IDENTITY

    def __init__(
        self,
        *,
        prepared: PreparedDue,
        lookup_repository: LookupRepository,
        events: list[str],
    ) -> None:
        self.runtime = RuntimeExecutor(
            scenario=prepared.scenario,
            fence=prepared.fence,
            events=events,
        )
        self.lookup_repository = lookup_repository

    @property
    def calls(self) -> list[tuple[str, str]]:
        return self.runtime.calls

    def execute(
        self,
        *,
        request_idempotency_key: str,
        delivery_idempotency_key: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        receipt = self.runtime.execute(
            request_idempotency_key=request_idempotency_key,
            delivery_idempotency_key=delivery_idempotency_key,
        )
        self.lookup_repository.add(receipt)
        return receipt


class NeverExecutor:
    runtime_store_identity = STORE_IDENTITY

    def __init__(self) -> None:
        self.calls = 0

    def execute(
        self,
        *,
        request_idempotency_key: str,
        delivery_idempotency_key: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        del request_idempotency_key, delivery_idempotency_key
        self.calls += 1
        raise AssertionError("durable-prefix repair attempted a new lookup")


@dataclass(slots=True)
class Harness:
    prepared: PreparedDue
    events: list[str]
    schedule: Schedule
    executor: Executor | NeverExecutor
    lookup: LookupRepository
    attempts: AttemptLoader
    ingress: IngressLoader
    reconciliation: ReconciliationRepository
    inbox: InboxRepository
    receipt: AlpacaPaperAuthenticatedLookupReceipt | None
    fact: BrokerReconciliationFact | None
    decision: BrokerInboxNonApplicationDecisionReceipt | None


def _terminal_decision(prepared: PreparedDue) -> Decision:
    return Decision(
        outcome=(AlpacaPaperUnknownRecoveryScheduleState.RECONCILIATION_REQUIRED),
        evaluation=prepared.evaluation,
        claim=None,
        newly_issued=False,
    )


def _fresh_harness() -> Harness:
    prepared = prepared_due()
    events: list[str] = []
    lookup = LookupRepository(events=events)
    schedule = Schedule(
        plan=prepared.plan,
        decision=Decision(
            outcome=AlpacaPaperUnknownRecoveryScheduleState.DUE,
            evaluation=prepared.evaluation,
            claim=prepared.claim,
            newly_issued=True,
        ),
        registered=False,
        events=events,
    )
    executor = Executor(
        prepared=prepared,
        lookup_repository=lookup,
        events=events,
    )
    return Harness(
        prepared=prepared,
        events=events,
        schedule=schedule,
        executor=executor,
        lookup=lookup,
        attempts=AttemptLoader(prepared.scenario.attempt, events=events),
        ingress=IngressLoader(prepared, events=events),
        reconciliation=ReconciliationRepository(events=events),
        inbox=InboxRepository(events=events),
        receipt=None,
        fact=None,
        decision=None,
    )


def _prefix_harness(stage: str) -> Harness:
    harness = _fresh_harness()
    assert isinstance(harness.executor, Executor)
    ticket = harness.prepared.claim.ticket
    receipt = harness.executor.execute(
        request_idempotency_key=ticket.demand_idempotency_key,
        delivery_idempotency_key=ticket.delivery_idempotency_key,
    )
    harness.events.clear()
    attached = stage != "lookup"
    harness.schedule = Schedule(
        plan=harness.prepared.plan,
        decision=_terminal_decision(harness.prepared),
        registered=True,
        dispatches=(
            DispatchProgress(
                claim=harness.prepared.claim,
                lookup_receipt=receipt if attached else None,
            ),
        ),
        events=harness.events,
    )
    harness.executor = NeverExecutor()
    harness.receipt = receipt
    if stage in {"reconciliation", "inbox"}:
        source = harness.prepared.scenario.lookups.evidence[-1].persisted_observation
        evidence = normalize_authenticated_alpaca_paper_lookup(receipt, source)
        harness.fact = harness.reconciliation.record(evidence)
        harness.reconciliation.record_calls = 0
        harness.events.clear()
    if stage == "inbox":
        assert harness.fact is not None
        request = create_alpaca_paper_inbox_admission_request(harness.fact)
        harness.decision = harness.inbox.record(request)
        harness.inbox.record_calls = 0
        harness.events.clear()
    return harness


def _run(harness: Harness) -> AlpacaPaperUnknownRecoveryPipelineResult:
    return run_alpaca_paper_unknown_recovery_pipeline_once(
        plan=harness.prepared.plan,
        fence=harness.prepared.fence,
        schedule=harness.schedule,
        executor=harness.executor,
        lookup_repository=harness.lookup,
        attempt_loader=harness.attempts,
        ingress_loader=harness.ingress,
        reconciliation_repository=harness.reconciliation,
        inbox_repository=harness.inbox,
    )


def test_fresh_due_step_composes_j_i_k_l_and_returns_non_authorizing_chain() -> None:
    harness = _fresh_harness()

    result = _run(harness)

    ticket = harness.prepared.claim.ticket
    assert result.lookup_executed is True
    assert result.observed_prefix_accounted is True
    assert result.observed_source_count == 1
    accounted = result.accounted_observations[0]
    assert accounted.ticket == ticket
    assert accounted.lookup_receipt is result.recovery_result.lookup_receipt
    assert (
        accounted.reconciliation_fact.evidence.source_lookup_receipt_id
        == accounted.lookup_receipt.receipt_id
    )
    assert accounted.inbox_decision.request.source_fact == (accounted.reconciliation_fact)
    assert harness.schedule.record_calls == 1
    assert isinstance(harness.executor, Executor)
    assert harness.executor.calls == [
        (ticket.demand_idempotency_key, ticket.delivery_idempotency_key)
    ]
    assert harness.reconciliation.record_calls == 1
    assert harness.inbox.record_calls == 1
    assert harness.events.index("evaluate") < harness.events.index("execute")
    assert harness.events.index("execute") < harness.events.index("record_observation")
    assert harness.events.index("record_observation") < harness.events.index(
        "reconciliation_record"
    )
    assert harness.events.index("reconciliation_record") < harness.events.index("inbox_record")
    for authority in (
        result.transport_authorized,
        result.broker_call_authorized,
        result.provider_deduplication_authorized,
        result.inbox_application_authorized,
        result.reconciliation_application_authorized,
        result.reconciliation_completion_authorized,
        result.unknown_resolution_authorized,
        result.reservation_release_authorized,
        result.lifecycle_application_authorized,
        result.canonical_execution_fact_authorized,
        result.resubmission_authorized,
        result.trading_effect_authorized,
        accounted.trading_effect_authorized,
    ):
        assert authority is False


@pytest.mark.parametrize(
    ("stage", "expected_schedule_records", "expected_k_records", "expected_l_records"),
    (
        ("lookup", 1, 1, 1),
        ("schedule", 0, 1, 1),
        ("reconciliation", 0, 0, 1),
        ("inbox", 0, 0, 0),
    ),
)
def test_each_durable_crash_prefix_resumes_without_another_lookup(
    stage: str,
    expected_schedule_records: int,
    expected_k_records: int,
    expected_l_records: int,
) -> None:
    harness = _prefix_harness(stage)
    assert harness.receipt is not None

    result = _run(harness)

    assert isinstance(harness.executor, NeverExecutor)
    assert harness.executor.calls == 0
    assert harness.schedule.record_calls == expected_schedule_records
    assert harness.reconciliation.record_calls == expected_k_records
    assert harness.inbox.record_calls == expected_l_records
    assert result.lookup_executed is False
    assert result.observed_source_count == 1
    accounted = result.accounted_observations[0]
    assert accounted.lookup_receipt == harness.receipt
    if harness.fact is not None:
        assert accounted.reconciliation_fact == harness.fact
    if harness.decision is not None:
        assert accounted.inbox_decision == harness.decision
    if stage == "lookup":
        assert harness.events.index("lookup_by_ingress") < harness.events.index(
            "record_observation"
        )
    assert harness.events.index("inbox_by_reconciliation") < harness.events.index("evaluate")


def test_waiting_schedule_has_no_lookup_or_downstream_effect() -> None:
    harness = _fresh_harness()
    waiting_at = harness.prepared.plan.unknown_recorded_at
    waiting = evaluate_unknown_submission_recovery(
        plan=harness.prepared.plan,
        evaluated_at=waiting_at,
    )
    harness.schedule.decision = Decision(
        outcome=AlpacaPaperUnknownRecoveryScheduleState.WAITING,
        evaluation=waiting,
        claim=None,
        newly_issued=False,
    )
    harness.executor = NeverExecutor()

    result = _run(harness)

    assert result.lookup_executed is False
    assert result.accounted_observations == ()
    assert harness.reconciliation.record_calls == 0
    assert harness.inbox.record_calls == 0
    assert isinstance(harness.executor, NeverExecutor)
    assert harness.executor.calls == 0


def test_split_store_fails_before_any_progress_read_or_effect() -> None:
    harness = _fresh_harness()
    harness.inbox.runtime_store_identity = STORE_IDENTITY + 1

    with pytest.raises(
        AlpacaPaperUnknownRecoveryPipelineConflict,
        match="do not share one durable store",
    ):
        _run(harness)

    assert harness.schedule.load_calls == 0
    assert harness.schedule.evaluate_calls == 0
    assert isinstance(harness.executor, Executor)
    assert harness.executor.calls == []
    assert harness.reconciliation.record_calls == 0
    assert harness.inbox.record_calls == 0


def test_prefix_failure_is_sanitized_and_blocks_new_schedule_evaluation() -> None:
    harness = _prefix_harness("schedule")
    harness.reconciliation.raise_on_source_load = True

    with pytest.raises(
        AlpacaPaperUnknownRecoveryPipelineExecutionError,
        match="Phase 4K crash-prefix read failed",
    ) as captured:
        _run(harness)

    assert "unsafe-k-secret" not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    assert harness.schedule.evaluate_calls == 0
    assert isinstance(harness.executor, NeverExecutor)
    assert harness.executor.calls == 0


def test_lookup_crash_prefix_mismatch_fails_before_ack_or_new_lookup() -> None:
    harness = _prefix_harness("lookup")
    assert harness.receipt is not None
    foreign = _fresh_harness()
    foreign_receipt = foreign.prepared.scenario.run(
        delivery_idempotency_key="phase4ac-foreign-delivery",
    )
    harness.lookup.by_ingress[harness.prepared.claim.ticket.delivery_id] = foreign_receipt

    with pytest.raises(
        AlpacaPaperUnknownRecoveryPipelineConflict,
        match="conflicts with its exact Phase 4J ticket",
    ):
        _run(harness)

    assert harness.schedule.record_calls == 0
    assert harness.schedule.evaluate_calls == 0
    assert isinstance(harness.executor, NeverExecutor)
    assert harness.executor.calls == 0


def test_invalid_store_identity_fails_before_callable_or_durable_access() -> None:
    harness = _fresh_harness()
    harness.lookup.runtime_store_identity = True

    with pytest.raises(
        AlpacaPaperUnknownRecoveryPipelineConflict,
        match="durable-store identity is invalid",
    ):
        _run(harness)

    assert harness.schedule.load_calls == 0


def test_result_and_accounted_observation_are_not_publicly_constructible() -> None:
    with pytest.raises(TypeError, match="workflow-produced"):
        AlpacaPaperUnknownRecoveryAccountedObservation()
    with pytest.raises(TypeError, match="workflow-produced"):
        AlpacaPaperUnknownRecoveryPipelineResult()


def test_progress_rejects_non_utc_claim_time_before_lookup_query() -> None:
    harness = _prefix_harness("lookup")
    naive = datetime(2026, 7, 15, 13, 32, 1)
    bad_claim = Claim(
        ticket=harness.prepared.claim.ticket,
        issued_at=naive,
        valid_until=naive + timedelta(seconds=3),
    )
    harness.schedule.dispatches = [DispatchProgress(claim=bad_claim, lookup_receipt=None)]

    with pytest.raises(
        AlpacaPaperUnknownRecoveryPipelineConflict,
        match="must be exact UTC",
    ):
        _run(harness)

    assert harness.lookup.ingress_load_calls == 0
    assert harness.schedule.evaluate_calls == 0


def test_wrong_account_fence_fails_before_port_access() -> None:
    harness = _fresh_harness()
    wrong = AccountFence(
        account_id="other-paper-account",
        owner_id=harness.prepared.fence.owner_id,
        lease_id=harness.prepared.fence.lease_id,
        fencing_generation=harness.prepared.fence.fencing_generation,
    )

    with pytest.raises(
        AlpacaPaperUnknownRecoveryPipelineConflict,
        match="belongs to another account",
    ):
        run_alpaca_paper_unknown_recovery_pipeline_once(
            plan=harness.prepared.plan,
            fence=wrong,
            schedule=harness.schedule,
            executor=harness.executor,
            lookup_repository=harness.lookup,
            attempt_loader=harness.attempts,
            ingress_loader=harness.ingress,
            reconciliation_repository=harness.reconciliation,
            inbox_repository=harness.inbox,
        )

    assert harness.schedule.load_calls == 0
