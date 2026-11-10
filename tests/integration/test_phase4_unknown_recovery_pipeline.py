from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pytest

from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    AlpacaPaperAuthenticatedLookupReceipt,
)
from packages.application.alpaca_paper_reconciliation_normalization import (
    normalize_and_record_authenticated_alpaca_paper_lookup,
)
from packages.application.alpaca_paper_unknown_recovery_pipeline import (
    AlpacaPaperUnknownRecoveryPipelineResult,
    run_alpaca_paper_unknown_recovery_pipeline_once,
)
from packages.application.broker_inbox_admission import (
    admit_authenticated_alpaca_paper_reconciliation_fact,
)
from packages.domain.unknown_submission_recovery import (
    UnknownSubmissionRecoveryPlan,
)
from packages.persistence.broker_inbox import SqlBrokerInboxRepository
from packages.persistence.broker_ingress import SqlBrokerIngressRepository
from packages.persistence.broker_reconciliation import (
    SqlBrokerReconciliationRepository,
)
from packages.persistence.unknown_submission_recovery import (
    SqlUnknownSubmissionRecoveryRepository,
)
from tests.integration.test_phase4_alpaca_paper_lookup_observation_persistence import (
    PreparedLookupPersistenceSystem,
    _prepared_system,
    _run_lookup,
)
from tests.integration.test_phase4_unknown_lookup_schedule_persistence import (
    _schedule,
)


@dataclass(slots=True)
class _SqlLookupExecutor:
    prepared: PreparedLookupPersistenceSystem
    lookup_at: datetime
    calls: int = 0

    @property
    def runtime_store_identity(self) -> int:
        return id(self.prepared.submission.engine)

    def execute(
        self,
        *,
        request_idempotency_key: str,
        delivery_idempotency_key: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        self.calls += 1
        return _run_lookup(
            self.prepared,
            lookup_at=self.lookup_at,
            request_idempotency_key=request_idempotency_key,
            delivery_idempotency_key=delivery_idempotency_key,
        )


@dataclass(frozen=True, slots=True)
class _PipelineSystem:
    prepared: PreparedLookupPersistenceSystem
    schedule: SqlUnknownSubmissionRecoveryRepository
    plan: UnknownSubmissionRecoveryPlan
    executor: _SqlLookupExecutor
    ingress: SqlBrokerIngressRepository
    reconciliation: SqlBrokerReconciliationRepository
    inbox: SqlBrokerInboxRepository


def _pipeline_system(path: Path) -> _PipelineSystem:
    prepared = _prepared_system(path)
    schedule, plan = _schedule(prepared)
    due_at = plan.slots[0].scheduled_at
    prepared.submission.coordinator_clock.instant = due_at
    return _PipelineSystem(
        prepared=prepared,
        schedule=schedule,
        plan=plan,
        executor=_SqlLookupExecutor(prepared=prepared, lookup_at=due_at),
        ingress=SqlBrokerIngressRepository(prepared.submission.engine),
        reconciliation=SqlBrokerReconciliationRepository(
            engine=prepared.submission.engine,
            clock=prepared.submission.coordinator_clock,
        ),
        inbox=SqlBrokerInboxRepository(
            engine=prepared.submission.engine,
            clock=prepared.submission.coordinator_clock,
        ),
    )


def _run_pipeline(system: _PipelineSystem) -> AlpacaPaperUnknownRecoveryPipelineResult:
    return run_alpaca_paper_unknown_recovery_pipeline_once(
        plan=system.plan,
        fence=system.prepared.submission.lease.fence,
        schedule=system.schedule,
        executor=system.executor,
        lookup_repository=system.prepared.repository,
        attempt_loader=system.prepared.submission.repository,
        ingress_loader=system.ingress,
        reconciliation_repository=system.reconciliation,
        inbox_repository=system.inbox,
    )


def _persist_prefix(system: _PipelineSystem, stage: str) -> None:
    plan = system.plan
    schedule = system.schedule
    decision = schedule.evaluate(
        plan,
        fence=system.prepared.submission.lease.fence,
    )
    claim = decision.claim
    assert claim is not None
    receipt = system.executor.execute(
        request_idempotency_key=claim.ticket.demand_idempotency_key,
        delivery_idempotency_key=claim.ticket.delivery_idempotency_key,
    )
    if stage == "lookup":
        return
    schedule.record_observation(
        plan_id=plan.plan_id,
        claim=claim,
        receipt=receipt,
        fence=system.prepared.submission.lease.fence,
    )
    if stage == "schedule":
        return
    fact = normalize_and_record_authenticated_alpaca_paper_lookup(
        receipt.receipt_id,
        lookup_loader=system.prepared.repository,
        attempt_loader=system.prepared.submission.repository,
        ingress_loader=system.ingress,
        reconciliation_repository=system.reconciliation,
    )
    if stage == "reconciliation":
        return
    decision_receipt = admit_authenticated_alpaca_paper_reconciliation_fact(
        fact.fact_id,
        reconciliation_loader=system.reconciliation,
        inbox_repository=system.inbox,
    )
    assert decision_receipt.request.source_fact == fact


def test_fresh_sql_pipeline_composes_one_lookup_through_non_applying_inbox(
    tmp_path: Path,
) -> None:
    system = _pipeline_system(tmp_path / "phase4ac-fresh.sqlite")

    result = _run_pipeline(system)

    assert result.lookup_executed is True
    assert result.observed_prefix_accounted is True
    assert result.observed_source_count == 1
    assert system.executor.calls == 1
    accounted = result.accounted_observations[0]
    assert accounted.lookup_receipt.ingress_receipt_id == accounted.ticket.delivery_id
    assert (
        accounted.reconciliation_fact.evidence.source_lookup_receipt_id
        == accounted.lookup_receipt.receipt_id
    )
    assert accounted.inbox_decision.request.source_fact == (accounted.reconciliation_fact)
    assert system.reconciliation.history(result.plan.account_id) == (accounted.reconciliation_fact,)
    assert system.inbox.history(result.plan.account_id) == (accounted.inbox_decision,)
    for field_name in (
        "transport_authorized",
        "broker_call_authorized",
        "inbox_application_authorized",
        "reconciliation_application_authorized",
        "reconciliation_completion_authorized",
        "unknown_resolution_authorized",
        "reservation_release_authorized",
        "lifecycle_application_authorized",
        "canonical_execution_fact_authorized",
        "resubmission_authorized",
        "trading_effect_authorized",
    ):
        assert getattr(result, field_name) is False
        assert getattr(accounted, field_name) is False


@pytest.mark.parametrize(
    "stage",
    (
        "lookup",
        "schedule",
        "reconciliation",
        "inbox",
    ),
)
def test_sql_pipeline_resumes_every_durable_prefix_without_another_lookup(
    tmp_path: Path,
    stage: str,
) -> None:
    system = _pipeline_system(tmp_path / f"phase4ac-{stage}.sqlite")
    _persist_prefix(system, stage)
    assert system.executor.calls == 1

    first_resume = _run_pipeline(system)
    second_resume = _run_pipeline(system)

    assert system.executor.calls == 1
    assert first_resume.lookup_executed is False
    assert second_resume.lookup_executed is False
    assert first_resume.accounted_observations == (second_resume.accounted_observations)
    assert first_resume.observed_source_count == 1
    accounted = first_resume.accounted_observations[0]
    assert system.reconciliation.history(first_resume.plan.account_id) == (
        accounted.reconciliation_fact,
    )
    assert system.inbox.history(first_resume.plan.account_id) == (accounted.inbox_decision,)
