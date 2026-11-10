from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from itertools import pairwise

import pytest
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from packages.application import trading_trace as trading_trace_module
from packages.application.trading_trace import (
    TradingTraceCompositionError,
    TradingTraceFacts,
    emit_available_trading_trace,
)
from packages.domain.account_coordinator import (
    AccountFence,
    AccountLease,
    _account_fence_receipt,
)
from packages.domain.batch_risk import BatchRiskAuthority
from packages.domain.clock import FixedClock
from packages.domain.ledger_reducer import reduce_execution_ledger
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.portfolio import portfolio_snapshot, target_to_intent_batch
from packages.domain.submission_attempt import (
    create_broker_submission_request,
    prepare_submission_attempt,
)
from packages.domain.walking_thread import WalkingThread
from packages.observability.tracing import (
    TradingTraceStage,
    build_tracer_provider,
)
from packages.risk.batch_repository import (
    InMemoryBatchRiskRepository,
    InMemoryBatchRiskSnapshotProvider,
)
from tests.unit.test_batch_risk import limits, snapshot


def _facts() -> TradingTraceFacts:
    walking = WalkingThread.run()
    market_batch = walking.decision_batch
    target = walking.target
    portfolio = portfolio_snapshot(
        as_of=market_batch.as_of,
        current_positions={},
        price_events=market_batch.events,
    )
    intent_batch = target_to_intent_batch(target, portfolio)
    risk_snapshot = snapshot(
        portfolio,
        account_id="trace-paper-account",
        available_cash=Decimal("100000"),
    )
    evaluated_at = market_batch.as_of + timedelta(seconds=1)
    decision = InMemoryBatchRiskRepository(
        BatchRiskAuthority(
            limits=limits(),
            snapshots=InMemoryBatchRiskSnapshotProvider(risk_snapshot),
            evaluation_clock=FixedClock(evaluated_at),
            consumption_clock=FixedClock(evaluated_at + timedelta(seconds=1)),
        )
    ).authorize(intent_batch, target)
    reservation = decision.reservation
    assert reservation is not None
    intent = intent_batch.intents[0]

    lease = AccountLease(
        account_id=decision.account_id,
        owner_id="trace-worker",
        lease_id="trace-lease",
        fencing_generation=1,
        revision_number=1,
        previous_lease_sha256=None,
        acquired_at=market_batch.as_of,
        heartbeat_at=market_batch.as_of,
        expires_at=evaluated_at + timedelta(minutes=1),
        policy_sha256="1" * 64,
    )
    prepared_at = evaluated_at + timedelta(seconds=1)
    receipt = _account_fence_receipt(
        fence=AccountFence(
            account_id=lease.account_id,
            owner_id=lease.owner_id,
            lease_id=lease.lease_id,
            fencing_generation=lease.fencing_generation,
        ),
        validated_at=prepared_at,
        valid_until=lease.expires_at,
        policy_sha256=lease.policy_sha256,
        lease_sha256=lease.semantic_sha256,
    )
    request = create_broker_submission_request(
        intent=intent,
        adapter_id="trace-fixture-broker",
        adapter_version="1.0.0",
        operation="submit_order",
        payload={"fixture": True},
    )
    attempt = prepare_submission_attempt(
        intent=intent,
        risk_decision=decision,
        fence_receipt=receipt,
        request=request,
        prepared_at=prepared_at,
        recorded_at=prepared_at,
        parent_attempts=(),
    )
    authorization = decision.authorizations[0]
    submission = create_order_submission(
        intent=intent,
        risk_decision_id=authorization.decision_id,
        submission_attempt_id=attempt.attempt_id,
        submitted_at=prepared_at,
    )
    execution = BrokerOrderEvent(
        event_id="trace-broker-execution-v1",
        order_id=submission.order_id,
        broker_order_id="trace-provider-order",
        broker_sequence=1,
        occurred_at=prepared_at + timedelta(seconds=1),
        received_at=prepared_at + timedelta(seconds=1, milliseconds=100),
        kind=BrokerOrderEventKind.EXECUTION,
        execution_id="trace-execution",
        execution_revision=1,
        quantity=intent.quantity,
        price=intent.reference_price,
        fee=Decimal("1"),
    )
    order_state = reduce_order_lifecycle(
        submission=submission,
        broker_events=(execution,),
    )
    entries = reduce_execution_ledger(
        order_states=(order_state,),
        execution_currency=decision.currency,
    ).entries
    assert len(entries) == 1
    return TradingTraceFacts(
        account_id=decision.account_id,
        environment="paper",
        market_batch=market_batch,
        target=target,
        intent_batch=intent_batch,
        reservation=reservation,
        submission_attempt=attempt.preparation,
        order_state=order_state,
        broker_event=execution,
        ledger_posting=entries[0],
    )


def test_exact_available_facts_emit_one_bounded_causal_trace() -> None:
    facts = _facts()
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    emission = emit_available_trading_trace(
        provider.get_tracer("tests.phase5e.composition"),
        facts,
    )

    expected_stages = (
        TradingTraceStage.MARKET_BATCH,
        TradingTraceStage.TARGET,
        TradingTraceStage.RESERVATION,
        TradingTraceStage.SUBMISSION_ATTEMPT,
        TradingTraceStage.BROKER_EVENT,
        TradingTraceStage.LEDGER_POSTING,
    )
    assert emission.attempted_stages == expected_stages
    assert emission.accepted_stages == expected_stages
    assert emission.instrumentation_error_class is None
    assert emission.export_confirmed is False
    assert emission.trading_authority_granted is False
    assert facts.missing_stages == (
        TradingTraceStage.FILL,
        TradingTraceStage.RECONCILIATION,
    )
    assert facts.complete is False

    spans = exporter.get_finished_spans()
    attributes = tuple(span.attributes for span in spans)
    assert all(item is not None for item in attributes)
    assert tuple(item["autoquant.stage"] for item in attributes if item is not None) == tuple(
        stage.value for stage in expected_stages
    )
    assert len({span.context.trace_id for span in spans}) == 1
    for previous, current in pairwise(spans):
        assert current.parent is not None
        assert current.parent.span_id == previous.context.span_id
    assert all(
        emission.correlation_sha256 == item["autoquant.correlation.sha256"]
        for item in attributes
        if item is not None
    )
    provider.shutdown()


def test_composition_rejects_a_ledger_entry_relabelled_to_another_event() -> None:
    facts = _facts()
    assert facts.ledger_posting is not None

    with pytest.raises(
        TradingTraceCompositionError,
        match="exact reducer result",
    ):
        replace(
            facts,
            ledger_posting=replace(
                facts.ledger_posting,
                source_sha256="f" * 64,
            ),
        )


class _FailingExporter(SpanExporter):
    def __init__(self) -> None:
        self.calls = 0

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self.calls += 1
        return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        return None


def test_async_export_failure_cannot_change_the_already_created_facts() -> None:
    facts = _facts()
    before = facts
    exporter = _FailingExporter()
    provider = build_tracer_provider(
        service_name="autoquant-trader",
        service_version="0.1.0",
        environment="paper",
        exporter=exporter,
    )

    emission = emit_available_trading_trace(
        provider.get_tracer("tests.phase5e.export-failure"),
        facts,
    )
    provider.force_flush(timeout_millis=1_000)

    assert emission.instrumentation_error_class is None
    assert emission.accepted_stages == emission.attempted_stages
    assert emission.export_confirmed is False
    assert emission.trading_authority_granted is False
    assert exporter.calls >= 1
    assert facts == before
    provider.shutdown()


def test_instrumentation_fault_is_sanitized_and_never_relabels_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = _facts()
    provider = TracerProvider()

    def fail_span(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RuntimeError("exporter detail with economic payload")

    monkeypatch.setattr(trading_trace_module, "trading_span", fail_span)
    emission = emit_available_trading_trace(
        provider.get_tracer("tests.phase5e.instrumentation-failure"),
        facts,
    )

    assert emission.accepted_stages == ()
    assert emission.instrumentation_error_class == "RuntimeError"
    assert emission.export_confirmed is False
    assert emission.trading_authority_granted is False
    assert "economic" not in repr(emission)
    provider.shutdown()
