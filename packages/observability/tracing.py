"""OpenTelemetry correlation for the trading decision and execution chain.

The helpers keep economic facts in their existing immutable domain contracts
and attach only opaque identities and digests to spans.  They intentionally use
W3C Trace Context without baggage so credentials, broker payloads, order
economics, or operator input cannot leak through propagation.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.propagators.textmap import Getter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.trace import Span, SpanKind, Tracer
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from packages.domain.canonical import canonical_json_bytes

TRADING_TRACE_CONTRACT_VERSION = "phase5e-trading-trace-correlation-v1"
MAX_TRACE_REFERENCES = 16
MAX_TRACE_CARRIER_VALUE_BYTES = 512
TRACE_EXPORT_QUEUE_SIZE = 2_048
TRACE_EXPORT_BATCH_SIZE = 256
TRACE_EXPORT_SCHEDULE_DELAY_MILLISECONDS = 1_000
TRACE_EXPORT_TIMEOUT_MILLISECONDS = 5_000

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TRACE_CARRIER_KEYS = frozenset({"traceparent", "tracestate"})
_TRACE_PROPAGATOR = TraceContextTextMapPropagator()


class TradingTraceError(ValueError):
    """Tracing evidence or a remote propagation carrier is malformed."""


class TradingTraceStage(StrEnum):
    MARKET_BATCH = "market_batch"
    TARGET = "target"
    RESERVATION = "reservation"
    SUBMISSION_ATTEMPT = "submission_attempt"
    BROKER_EVENT = "broker_event"
    FILL = "fill"
    LEDGER_POSTING = "ledger_posting"
    RECONCILIATION = "reconciliation"


_STAGE_ORDER = {stage: index for index, stage in enumerate(TradingTraceStage)}


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise TradingTraceError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise TradingTraceError(f"{field_name} contains unsupported text")


@dataclass(frozen=True, slots=True)
class TradingTraceReference:
    """One immutable domain fact made visible to a trace."""

    stage: TradingTraceStage
    fact_id: str
    fact_sha256: str

    def __post_init__(self) -> None:
        if type(self.stage) is not TradingTraceStage:
            raise TradingTraceError("trading trace stage is unsupported")
        _require_text(self.fact_id, "trading trace fact ID", maximum=256)
        if type(self.fact_sha256) is not str or _SHA256.fullmatch(self.fact_sha256) is None:
            raise TradingTraceError("trading trace fact_sha256 must be a lowercase SHA-256 digest")

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    TRADING_TRACE_CONTRACT_VERSION,
                    "reference",
                    self.stage,
                    self.fact_id,
                    self.fact_sha256,
                )
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class TradingTraceCorrelation:
    """A bounded canonical causal chain attached to one or more spans."""

    account_id: str
    environment: str
    references: tuple[TradingTraceReference, ...]

    def __post_init__(self) -> None:
        _require_text(self.account_id, "trading trace account ID", maximum=64)
        _require_text(self.environment, "trading trace environment", maximum=32)
        if type(self.references) is not tuple or not self.references:
            raise TradingTraceError(
                "trading trace correlation requires a non-empty exact reference tuple"
            )
        if len(self.references) > MAX_TRACE_REFERENCES:
            raise TradingTraceError("trading trace correlation exceeds its reference bound")
        if any(type(item) is not TradingTraceReference for item in self.references):
            raise TradingTraceError("trading trace references must be exact")
        stages = tuple(item.stage for item in self.references)
        if len(stages) != len(set(stages)):
            raise TradingTraceError("trading trace correlation repeats a stage")
        if self.references != tuple(
            sorted(self.references, key=lambda item: _STAGE_ORDER[item.stage])
        ):
            raise TradingTraceError("trading trace references must follow causal stage order")

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    TRADING_TRACE_CONTRACT_VERSION,
                    "correlation",
                    self.account_id,
                    self.environment,
                    tuple(item.semantic_sha256 for item in self.references),
                )
            )
        ).hexdigest()

    def require_stage(self, stage: TradingTraceStage) -> None:
        if type(stage) is not TradingTraceStage:
            raise TradingTraceError("trading span stage is unsupported")
        if all(item.stage is not stage for item in self.references):
            raise TradingTraceError("trading span stage is absent from its correlation")

    @property
    def span_attributes(self) -> dict[str, str]:
        attributes = {
            "autoquant.trace.contract": TRADING_TRACE_CONTRACT_VERSION,
            "autoquant.correlation.sha256": self.semantic_sha256,
            "autoquant.account.id": self.account_id,
            "autoquant.environment": self.environment,
        }
        for reference in self.references:
            prefix = f"autoquant.{reference.stage.value}"
            attributes[f"{prefix}.id"] = reference.fact_id
            attributes[f"{prefix}.sha256"] = reference.fact_sha256
        return attributes


@contextmanager
def trading_span(
    tracer: Tracer,
    *,
    operation: str,
    stage: TradingTraceStage,
    correlation: TradingTraceCorrelation,
    parent_context: Context | None = None,
    kind: SpanKind = SpanKind.INTERNAL,
) -> Iterator[Span]:
    """Start one correlated span under the current or explicitly extracted context."""

    if not isinstance(tracer, Tracer):
        raise TradingTraceError("trading span requires an OpenTelemetry Tracer")
    _require_text(operation, "trading span operation", maximum=128)
    if type(correlation) is not TradingTraceCorrelation:
        raise TradingTraceError("trading span requires an exact correlation")
    correlation.__post_init__()
    correlation.require_stage(stage)
    if type(kind) is not SpanKind:
        raise TradingTraceError("trading span kind is unsupported")
    attributes = correlation.span_attributes
    attributes["autoquant.stage"] = stage.value
    with tracer.start_as_current_span(
        operation,
        context=parent_context,
        kind=kind,
        attributes=attributes,
    ) as span:
        yield span


def inject_current_trace_context() -> dict[str, str]:
    """Return a W3C-only propagation carrier for the current valid span."""

    current = trace.get_current_span().get_span_context()
    if not current.is_valid:
        raise TradingTraceError("no valid current span exists for trace propagation")
    carrier: dict[str, str] = {}
    _TRACE_PROPAGATOR.inject(carrier)
    _validate_trace_carrier(carrier)
    return carrier


class _ExactCarrierGetter(Getter[Mapping[str, str]]):
    def get(self, carrier: Mapping[str, str], key: str) -> list[str] | None:
        value = carrier.get(key)
        return None if value is None else [value]

    def keys(self, carrier: Mapping[str, str]) -> list[str]:
        return list(carrier)


_EXACT_CARRIER_GETTER = _ExactCarrierGetter()


def _validate_trace_carrier(carrier: Mapping[str, str]) -> None:
    if not isinstance(carrier, Mapping):
        raise TradingTraceError("trace carrier must be a mapping")
    if set(carrier) - _TRACE_CARRIER_KEYS or "traceparent" not in carrier:
        raise TradingTraceError(
            "trace carrier must contain traceparent and optional tracestate only"
        )
    for key, value in carrier.items():
        if type(key) is not str or key != key.lower():
            raise TradingTraceError("trace carrier keys must be canonical lowercase text")
        if type(value) is not str or not value or value != value.strip():
            raise TradingTraceError("trace carrier values must be non-empty trimmed text")
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as error:
            raise TradingTraceError("trace carrier values must be ASCII") from error
        if len(encoded) > MAX_TRACE_CARRIER_VALUE_BYTES:
            raise TradingTraceError("trace carrier value exceeds its byte bound")


def extract_remote_trace_context(carrier: Mapping[str, str]) -> Context:
    """Validate and extract an exact W3C remote parent without accepting baggage."""

    _validate_trace_carrier(carrier)
    context = _TRACE_PROPAGATOR.extract(
        carrier=carrier,
        getter=_EXACT_CARRIER_GETTER,
    )
    if not trace.get_current_span(context).get_span_context().is_valid:
        raise TradingTraceError("trace carrier does not contain a valid W3C trace context")
    return context


def build_tracer_provider(
    *,
    service_name: str,
    service_version: str,
    environment: str,
    exporter: SpanExporter,
) -> TracerProvider:
    """Build, but do not globally install, the fixed asynchronous SDK provider."""

    _require_text(service_name, "trace service name")
    _require_text(service_version, "trace service version", maximum=64)
    _require_text(environment, "trace deployment environment", maximum=32)
    if not isinstance(exporter, SpanExporter):
        raise TradingTraceError("trace exporter must implement the OpenTelemetry SDK contract")
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": service_name,
                "service.version": service_version,
                "deployment.environment.name": environment,
                "autoquant.trace.contract": TRADING_TRACE_CONTRACT_VERSION,
            }
        )
    )
    provider.add_span_processor(
        BatchSpanProcessor(
            exporter,
            max_queue_size=TRACE_EXPORT_QUEUE_SIZE,
            schedule_delay_millis=TRACE_EXPORT_SCHEDULE_DELAY_MILLISECONDS,
            max_export_batch_size=TRACE_EXPORT_BATCH_SIZE,
            export_timeout_millis=TRACE_EXPORT_TIMEOUT_MILLISECONDS,
        )
    )
    return provider
