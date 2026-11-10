from __future__ import annotations

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind

from packages.observability.tracing import (
    TRADING_TRACE_CONTRACT_VERSION,
    TradingTraceCorrelation,
    TradingTraceError,
    TradingTraceReference,
    TradingTraceStage,
    build_tracer_provider,
    extract_remote_trace_context,
    inject_current_trace_context,
    trading_span,
)


def _synthetic_contract_correlation() -> TradingTraceCorrelation:
    """Exercise the closed low-level schema; this is not runtime fact evidence."""

    return TradingTraceCorrelation(
        account_id="paper-account-1",
        environment="paper",
        references=tuple(
            TradingTraceReference(
                stage=stage,
                fact_id=f"{stage.value}-id",
                fact_sha256=f"{index + 1:064x}",
            )
            for index, stage in enumerate(TradingTraceStage)
        ),
    )


def _tracer() -> tuple[TracerProvider, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


def test_low_level_eight_stage_contract_is_attached_as_opaque_span_attributes() -> None:
    provider, exporter = _tracer()
    tracer = provider.get_tracer("tests.phase5e")
    correlation = _synthetic_contract_correlation()

    with trading_span(
        tracer,
        operation="reconcile.account",
        stage=TradingTraceStage.RECONCILIATION,
        correlation=correlation,
        kind=SpanKind.INTERNAL,
    ):
        pass

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    attributes = spans[0].attributes
    assert attributes is not None
    assert attributes["autoquant.trace.contract"] == TRADING_TRACE_CONTRACT_VERSION
    assert attributes["autoquant.correlation.sha256"] == correlation.semantic_sha256
    assert attributes["autoquant.stage"] == "reconciliation"
    for reference in correlation.references:
        prefix = f"autoquant.{reference.stage.value}"
        assert attributes[f"{prefix}.id"] == reference.fact_id
        assert attributes[f"{prefix}.sha256"] == reference.fact_sha256
    provider.shutdown()


def test_w3c_carrier_preserves_trace_across_an_explicit_remote_parent() -> None:
    first_provider, first_exporter = _tracer()
    second_provider, second_exporter = _tracer()
    first_tracer = first_provider.get_tracer("tests.producer")
    second_tracer = second_provider.get_tracer("tests.consumer")
    correlation = _synthetic_contract_correlation()

    with trading_span(
        first_tracer,
        operation="submit.order",
        stage=TradingTraceStage.SUBMISSION_ATTEMPT,
        correlation=correlation,
        kind=SpanKind.PRODUCER,
    ):
        carrier = inject_current_trace_context()
    remote_context = extract_remote_trace_context(carrier)
    with trading_span(
        second_tracer,
        operation="ingest.broker-event",
        stage=TradingTraceStage.BROKER_EVENT,
        correlation=correlation,
        parent_context=remote_context,
        kind=SpanKind.CONSUMER,
    ):
        pass

    producer = first_exporter.get_finished_spans()[0]
    consumer = second_exporter.get_finished_spans()[0]
    assert set(carrier) <= {"traceparent", "tracestate"}
    assert producer.context.trace_id == consumer.context.trace_id
    assert consumer.parent is not None
    assert consumer.parent.span_id == producer.context.span_id
    first_provider.shutdown()
    second_provider.shutdown()


@pytest.mark.parametrize(
    "carrier",
    (
        {},
        {"traceparent": "not-valid"},
        {"traceparent": "00-" + "1" * 32 + "-" + "2" * 16 + "-01", "baggage": "secret=x"},
        {"Traceparent": "00-" + "1" * 32 + "-" + "2" * 16 + "-01"},
    ),
)
def test_remote_carrier_is_strict_and_never_accepts_baggage(
    carrier: dict[str, str],
) -> None:
    with pytest.raises(TradingTraceError):
        extract_remote_trace_context(carrier)


def test_correlation_rejects_duplicate_or_out_of_order_stages() -> None:
    first = TradingTraceReference(
        stage=TradingTraceStage.TARGET,
        fact_id="target",
        fact_sha256="a" * 64,
    )
    second = TradingTraceReference(
        stage=TradingTraceStage.MARKET_BATCH,
        fact_id="batch",
        fact_sha256="b" * 64,
    )
    with pytest.raises(TradingTraceError, match="causal stage order"):
        TradingTraceCorrelation(
            account_id="paper-account-1",
            environment="paper",
            references=(first, second),
        )
    with pytest.raises(TradingTraceError, match="repeats"):
        TradingTraceCorrelation(
            account_id="paper-account-1",
            environment="paper",
            references=(first, first),
        )


def test_span_stage_must_be_present_in_the_exact_correlation() -> None:
    provider, _ = _tracer()
    tracer = provider.get_tracer("tests.stage")
    correlation = TradingTraceCorrelation(
        account_id="paper-account-1",
        environment="paper",
        references=(
            TradingTraceReference(
                stage=TradingTraceStage.MARKET_BATCH,
                fact_id="batch",
                fact_sha256="a" * 64,
            ),
        ),
    )

    with (
        pytest.raises(TradingTraceError, match="absent"),
        trading_span(
            tracer,
            operation="target.create",
            stage=TradingTraceStage.TARGET,
            correlation=correlation,
        ),
    ):
        pass
    provider.shutdown()


def test_sdk_provider_has_fixed_service_resource_and_exports_asynchronously() -> None:
    exporter = InMemorySpanExporter()
    provider = build_tracer_provider(
        service_name="autoquant-trader",
        service_version="0.1.0",
        environment="paper",
        exporter=exporter,
    )
    tracer = provider.get_tracer("tests.provider")

    with trading_span(
        tracer,
        operation="market.consume",
        stage=TradingTraceStage.MARKET_BATCH,
        correlation=TradingTraceCorrelation(
            account_id="paper-account-1",
            environment="paper",
            references=(
                TradingTraceReference(
                    stage=TradingTraceStage.MARKET_BATCH,
                    fact_id="batch",
                    fact_sha256="a" * 64,
                ),
            ),
        ),
    ):
        pass

    assert provider.force_flush(timeout_millis=1_000)
    span = exporter.get_finished_spans()[0]
    assert span.resource.attributes["service.name"] == "autoquant-trader"
    assert span.resource.attributes["service.version"] == "0.1.0"
    assert span.resource.attributes["deployment.environment.name"] == "paper"
    provider.shutdown()
