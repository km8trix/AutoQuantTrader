"""Bounded, non-authorizing composition for trading-chain telemetry.

This module adapts exact immutable domain facts to the low-level OpenTelemetry
contract.  It does not prove that a fact is durable, authorize an effect, or
promote historical broker observations into canonical lifecycle facts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.trace import SpanKind, Tracer

from packages.domain.batch_risk import BatchRiskReservation
from packages.domain.ledger_reducer import (
    CanonicalLedgerEntry,
    LedgerEntryKind,
    reduce_execution_ledger,
)
from packages.domain.market_batch import MarketBatch
from packages.domain.models import OrderIntentBatch, TargetPortfolio
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    reduce_order_lifecycle,
)
from packages.domain.submission_attempt import SubmissionAttemptPreparation
from packages.observability.tracing import (
    TradingTraceCorrelation,
    TradingTraceError,
    TradingTraceReference,
    TradingTraceStage,
    trading_span,
)

_TRACE_OPERATION_BY_STAGE = {
    TradingTraceStage.MARKET_BATCH: "autoquant.trading.market_batch",
    TradingTraceStage.TARGET: "autoquant.trading.target",
    TradingTraceStage.RESERVATION: "autoquant.trading.reservation",
    TradingTraceStage.SUBMISSION_ATTEMPT: "autoquant.trading.submission_attempt",
    TradingTraceStage.BROKER_EVENT: "autoquant.trading.broker_event",
    TradingTraceStage.LEDGER_POSTING: "autoquant.trading.ledger_posting",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ERROR_CLASS = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class TradingTraceCompositionError(TradingTraceError):
    """Exact domain facts do not form the claimed causal trace."""


def _require_exact(
    value: object | None,
    expected_type: type[object],
    field_name: str,
) -> None:
    if value is not None and type(value) is not expected_type:
        raise TradingTraceCompositionError(
            f"{field_name} must be an exact {expected_type.__name__}"
        )


@dataclass(frozen=True, slots=True)
class TradingTraceFacts:
    """The currently representable prefix/subset of one order's causal chain.

    ``intent_batch`` and ``order_state`` are proof inputs, not trace stages.
    There is deliberately no reconciliation input yet: the current Phase 4
    reconciliation fact is historical, non-applying evidence and must not be
    presented as an authoritative reconciliation result.  Likewise, the
    transient advanced-risk fill input is not a durable correction-safe fill
    fact, so this composition does not claim the ``fill`` stage.
    """

    account_id: str
    environment: str
    market_batch: MarketBatch | None = None
    target: TargetPortfolio | None = None
    intent_batch: OrderIntentBatch | None = None
    reservation: BatchRiskReservation | None = None
    submission_attempt: SubmissionAttemptPreparation | None = None
    order_state: CanonicalOrderState | None = None
    broker_event: BrokerOrderEvent | None = None
    ledger_posting: CanonicalLedgerEntry | None = None

    def __post_init__(self) -> None:
        for value, expected_type, field_name in (
            (self.market_batch, MarketBatch, "market_batch"),
            (self.target, TargetPortfolio, "target"),
            (self.intent_batch, OrderIntentBatch, "intent_batch"),
            (self.reservation, BatchRiskReservation, "reservation"),
            (
                self.submission_attempt,
                SubmissionAttemptPreparation,
                "submission_attempt",
            ),
            (self.order_state, CanonicalOrderState, "order_state"),
            (self.broker_event, BrokerOrderEvent, "broker_event"),
            (self.ledger_posting, CanonicalLedgerEntry, "ledger_posting"),
        ):
            _require_exact(value, expected_type, field_name)
        self._validate_dependencies()
        self._validate_causality()
        # Reuse the low-level bounds and account/environment validation.
        self.correlation.__post_init__()

    def _validate_dependencies(self) -> None:
        if self.target is None and any(
            value is not None
            for value in (
                self.intent_batch,
                self.reservation,
                self.submission_attempt,
                self.order_state,
                self.broker_event,
                self.ledger_posting,
            )
        ):
            raise TradingTraceCompositionError(
                "downstream trading facts require their exact target"
            )
        if self.reservation is None and any(
            value is not None
            for value in (
                self.submission_attempt,
                self.order_state,
                self.broker_event,
                self.ledger_posting,
            )
        ):
            raise TradingTraceCompositionError(
                "submission and execution facts require their exact reservation"
            )
        if self.reservation is not None and self.intent_batch is None:
            raise TradingTraceCompositionError(
                "reservation correlation requires its exact intent batch"
            )
        if self.submission_attempt is None and any(
            value is not None
            for value in (
                self.order_state,
                self.broker_event,
                self.ledger_posting,
            )
        ):
            raise TradingTraceCompositionError(
                "broker and ledger facts require their exact submission attempt"
            )
        if (self.order_state is None) != (self.broker_event is None):
            raise TradingTraceCompositionError(
                "broker-event correlation requires its canonical order state"
            )
        if self.ledger_posting is not None and self.broker_event is None:
            raise TradingTraceCompositionError("ledger correlation requires its exact broker event")

    def _validate_causality(self) -> None:
        market_batch = self.market_batch
        target = self.target
        intent_batch = self.intent_batch
        reservation = self.reservation
        preparation = self.submission_attempt
        order_state = self.order_state
        broker_event = self.broker_event
        ledger_posting = self.ledger_posting

        if market_batch is not None:
            market_batch._validate()
            if not market_batch.complete:
                raise TradingTraceCompositionError("trading trace requires a complete market batch")
        if target is not None:
            target.__post_init__()
            if market_batch is not None:
                try:
                    target.decision_trigger.require_market_batch(market_batch)
                except ValueError as error:
                    raise TradingTraceCompositionError(str(error)) from error
        if intent_batch is not None:
            intent_batch.__post_init__()
            if target is None or (
                intent_batch.target_id != target.target_id
                or intent_batch.target_sha256 != target.semantic_sha256
                or intent_batch.decision_trigger != target.decision_trigger
            ):
                raise TradingTraceCompositionError("intent batch is not bound to the exact target")
        if reservation is not None:
            reservation.__post_init__()
            if intent_batch is None or (
                reservation.intent_batch_id != intent_batch.intent_batch_id
                or reservation.intent_batch_sha256 != intent_batch.semantic_sha256
            ):
                raise TradingTraceCompositionError(
                    "reservation is not bound to the exact intent batch"
                )
        if preparation is not None:
            preparation._validate()
            assert intent_batch is not None
            if reservation is None or (
                preparation.account_id != self.account_id
                or preparation.reservation_id != reservation.reservation_id
                or preparation.risk_decision.reservation != reservation
                or preparation.intent not in intent_batch.intents
            ):
                raise TradingTraceCompositionError(
                    "submission attempt is not bound to the exact account, batch, and reservation"
                )
        if order_state is not None and broker_event is not None:
            canonical = reduce_order_lifecycle(
                submission=order_state.submission,
                broker_events=order_state.broker_events,
                cancel_request=order_state.cancel_request,
            )
            if canonical != order_state:
                raise TradingTraceCompositionError(
                    "order state is not the exact canonical reducer result"
                )
            if preparation is None or (
                order_state.submission.submission_attempt_id != preparation.attempt_id
                or broker_event not in order_state.broker_events
            ):
                raise TradingTraceCompositionError(
                    "broker event is not bound to the exact submission and order state"
                )
        if ledger_posting is not None and broker_event is not None:
            ledger_posting.__post_init__()
            if broker_event.kind not in {
                BrokerOrderEventKind.EXECUTION,
                BrokerOrderEventKind.EXECUTION_CORRECTION,
            }:
                raise TradingTraceCompositionError(
                    "ledger posting requires an execution broker event"
                )
            if order_state is None:
                raise TradingTraceCompositionError(
                    "ledger posting requires its canonical order state"
                )
            currencies = {posting.currency for posting in ledger_posting.postings}
            if len(currencies) != 1:
                raise TradingTraceCompositionError(
                    "ledger posting must retain one exact execution currency"
                )
            expected = tuple(
                entry
                for entry in reduce_execution_ledger(
                    order_states=(order_state,),
                    execution_currency=next(iter(currencies)),
                ).entries
                if entry.reference_id == broker_event.event_id
            )
            expected_kind = (
                LedgerEntryKind.EXECUTION
                if broker_event.kind is BrokerOrderEventKind.EXECUTION
                else LedgerEntryKind.EXECUTION_CORRECTION
            )
            if (
                len(expected) != 1
                or expected[0] != ledger_posting
                or ledger_posting.kind is not expected_kind
                or ledger_posting.source_sha256 != broker_event.semantic_sha256
            ):
                raise TradingTraceCompositionError(
                    "ledger posting is not the exact reducer result for the broker event"
                )

    @property
    def references(self) -> tuple[TradingTraceReference, ...]:
        references: list[TradingTraceReference] = []
        if self.market_batch is not None:
            references.append(
                TradingTraceReference(
                    stage=TradingTraceStage.MARKET_BATCH,
                    fact_id=self.market_batch.batch_id,
                    fact_sha256=self.market_batch.semantic_sha256,
                )
            )
        if self.target is not None:
            references.append(
                TradingTraceReference(
                    stage=TradingTraceStage.TARGET,
                    fact_id=self.target.target_id,
                    fact_sha256=self.target.semantic_sha256,
                )
            )
        if self.reservation is not None:
            references.append(
                TradingTraceReference(
                    stage=TradingTraceStage.RESERVATION,
                    fact_id=self.reservation.reservation_id,
                    fact_sha256=self.reservation.semantic_sha256,
                )
            )
        if self.submission_attempt is not None:
            references.append(
                TradingTraceReference(
                    stage=TradingTraceStage.SUBMISSION_ATTEMPT,
                    fact_id=self.submission_attempt.attempt_id,
                    fact_sha256=self.submission_attempt.semantic_sha256,
                )
            )
        if self.broker_event is not None:
            references.append(
                TradingTraceReference(
                    stage=TradingTraceStage.BROKER_EVENT,
                    fact_id=self.broker_event.event_id,
                    fact_sha256=self.broker_event.semantic_sha256,
                )
            )
        if self.ledger_posting is not None:
            references.append(
                TradingTraceReference(
                    stage=TradingTraceStage.LEDGER_POSTING,
                    fact_id=self.ledger_posting.entry_id,
                    fact_sha256=self.ledger_posting.semantic_sha256,
                )
            )
        return tuple(references)

    @property
    def correlation(self) -> TradingTraceCorrelation:
        return TradingTraceCorrelation(
            account_id=self.account_id,
            environment=self.environment,
            references=self.references,
        )

    @property
    def missing_stages(self) -> tuple[TradingTraceStage, ...]:
        present = frozenset(reference.stage for reference in self.references)
        return tuple(stage for stage in TradingTraceStage if stage not in present)

    @property
    def complete(self) -> bool:
        return not self.missing_stages


@dataclass(frozen=True, slots=True)
class TradingTraceEmission:
    """Best-effort instrumentation outcome; never evidence of export or authority."""

    correlation_sha256: str
    attempted_stages: tuple[TradingTraceStage, ...]
    accepted_stages: tuple[TradingTraceStage, ...]
    instrumentation_error_class: str | None
    export_confirmed: bool = field(default=False, init=False)
    trading_authority_granted: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (
            type(self.correlation_sha256) is not str
            or _SHA256.fullmatch(self.correlation_sha256) is None
        ):
            raise TradingTraceCompositionError(
                "trace emission correlation must be a lowercase SHA-256 digest"
            )
        if (
            type(self.attempted_stages) is not tuple
            or type(self.accepted_stages) is not tuple
            or any(
                type(stage) is not TradingTraceStage
                for stage in self.attempted_stages + self.accepted_stages
            )
            or self.accepted_stages != self.attempted_stages[: len(self.accepted_stages)]
        ):
            raise TradingTraceCompositionError(
                "trace emission stages must be an exact accepted prefix"
            )
        if self.instrumentation_error_class is None:
            if self.accepted_stages != self.attempted_stages:
                raise TradingTraceCompositionError(
                    "successful trace instrumentation must accept every attempted stage"
                )
        elif (
            type(self.instrumentation_error_class) is not str
            or _ERROR_CLASS.fullmatch(self.instrumentation_error_class) is None
        ):
            raise TradingTraceCompositionError("trace instrumentation failure class is malformed")


def emit_available_trading_trace(
    tracer: Tracer,
    facts: TradingTraceFacts,
    *,
    parent_context: Context | None = None,
) -> TradingTraceEmission:
    """Emit a bounded same-trace span chain after domain facts already exist.

    Instrumentation failures are converted to a sanitized result.  This helper
    owns no repository, broker, control, or authorization port and therefore
    cannot roll back, approve, or mutate a trading fact.
    """

    if type(facts) is not TradingTraceFacts:
        raise TradingTraceCompositionError("trace emission requires exact TradingTraceFacts")
    facts.__post_init__()
    correlation = facts.correlation
    attempted = tuple(reference.stage for reference in correlation.references)
    accepted: list[TradingTraceStage] = []
    current_parent = parent_context
    for stage in attempted:
        try:
            with trading_span(
                tracer,
                operation=_TRACE_OPERATION_BY_STAGE[stage],
                stage=stage,
                correlation=correlation,
                parent_context=current_parent,
                kind=SpanKind.INTERNAL,
            ) as span:
                current_parent = trace.set_span_in_context(span, current_parent)
                accepted.append(stage)
        except Exception as error:
            error_class = type(error).__name__
            if _ERROR_CLASS.fullmatch(error_class) is None:
                error_class = "InstrumentationError"
            return TradingTraceEmission(
                correlation_sha256=correlation.semantic_sha256,
                attempted_stages=attempted,
                accepted_stages=tuple(accepted),
                instrumentation_error_class=error_class,
            )
    return TradingTraceEmission(
        correlation_sha256=correlation.semantic_sha256,
        attempted_stages=attempted,
        accepted_stages=tuple(accepted),
        instrumentation_error_class=None,
    )


__all__ = [
    "TradingTraceCompositionError",
    "TradingTraceEmission",
    "TradingTraceFacts",
    "emit_available_trading_trace",
]
