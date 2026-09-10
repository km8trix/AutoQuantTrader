"""The daily engine's sole deterministic, knowledge-frontier scheduler.

Financial postings, execution corrections and FIFO remain behind the injected
accounting port. Drivers provide immutable facts, never a future-aware account.
"""

from __future__ import annotations

import heapq
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal, localcontext
from time import monotonic
from typing import Literal
from zoneinfo import ZoneInfo

from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingState,
    AccountingTransition,
    AccountSnapshot,
    ActivateCommitment,
    Commitment,
    ControlCommand,
    DueAccountingEvent,
    ExecutionAccountingPort,
    ExecutionObservation,
    InstallCommitment,
    ModelDisposition,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.daily_risk import evaluate_daily_risk
from packages.domain.decimal_math import exact_decimal_add as add
from packages.domain.decimal_math import exact_decimal_multiply as mul
from packages.domain.engine_contracts import (
    BenchmarkPrice,
    DailyIntentBatch,
    DailyPrice,
    DailyRiskEvidence,
    DailyStrategy,
    DailyStrategyContext,
    DailyStrategyState,
    DailyTarget,
    DailyTrigger,
    EngineEvent,
    EngineInputs,
    EngineTraceRow,
    ObservationProvenance,
    ScheduleSignal,
)
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import CashFlowKind, LedgerCashFlow, create_cash_flow
from packages.domain.order_reducer import (
    BrokerOrderEventKind,
    OrderCancelRequest,
    create_order_submission,
)
from packages.domain.personal_contracts import (
    CausalMark,
    ReductionPoint,
    content_digest,
    semantic_value,
)
from packages.domain.portfolio import daily_target_to_intents
from packages.domain.report_contracts import (
    BenchmarkValuationInput,
    EngineResult,
    ExternalFlowRow,
    ScoredInterval,
    ValuationRole,
    ValuationRow,
)
from packages.domain.research_dataset import modeled_daily_availability
from packages.domain.wealth import WealthPoint, derive_wealth_path, derived_context


class _Stop(Exception):
    def __init__(self, status: Literal["cancelled", "failed", "rejected"], reason: str) -> None:
        self.status, self.reason = status, reason


class _SimulatedRequests:
    """Explicit modeled order/cancel requests; never evidence of provider quota."""

    def __init__(self) -> None:
        self.rows: list[tuple[datetime, bool]] = []

    def permits(self, at: datetime, count: int, *, low_priority: bool) -> bool:
        self.rows = [
            (instant, low) for instant, low in self.rows if instant > at - timedelta(seconds=60)
        ]
        return len(self.rows) + count <= 20 and (
            not low_priority or sum(low for _, low in self.rows) + count <= 10
        )

    def record(self, at: datetime, *, low_priority: bool) -> None:
        if not self.permits(at, 1, low_priority=low_priority):
            raise _Stop("rejected", "SIMULATED_REQUEST_CAPACITY_EXHAUSTED")
        self.rows.append((at, low_priority))


def _cutoff(session: date) -> datetime:
    return datetime.combine(session, time(9), ZoneInfo("America/New_York")).astimezone(UTC)


def _stage(event: EngineEvent) -> int:
    payload = event.payload
    if isinstance(payload, AccountingCommand):
        return 0 if isinstance(payload.payload, ControlCommand) else 1
    if isinstance(payload, (DailyPrice, BenchmarkPrice)):
        return 2
    if isinstance(payload, ExecutionObservation):
        return 3
    return 5


class _Engine:
    def __init__(
        self,
        inputs: EngineInputs,
        accounting: ExecutionAccountingPort,
        strategy: DailyStrategy,
        stop_requested: Callable[[], bool] | None,
    ) -> None:
        self.inputs, self.spec = inputs, inputs.spec
        self.accounting, self.strategy, self.stop_requested = accounting, strategy, stop_requested
        self.started = monotonic()
        self.requests = _SimulatedRequests()
        self.state = inputs.initial_state
        self.strategy_state = DailyStrategyState()
        self.sessions = {item.session_label: item for item in self.spec.calendar.sessions}
        self.labels = tuple(self.sessions)
        self.scored = self.spec.evaluation.scored_sessions
        self.expected = (*self.spec.evaluation.warmup_sessions, *self.scored)
        self.now = self.sessions[self.expected[0]].opens_at
        self.economic = self.now
        self.mark_session = self.expected[0]
        retained_points = tuple(point for _, point in self.state.event_points)
        self.frontier = max((point.frontier_sequence for point in retained_points), default=0)
        self.sequence = max((point.reduction_sequence for point in retained_points), default=0)
        self.sequence = max(self.sequence, self.state.revision)
        self.processed = self.output_bytes = 0
        self.retained_knowledge = max(
            (
                item
                for item in (
                    *(point.knowledge_at for point in retained_points),
                    *(flow.recorded_at for flow in self.state.cash_flows),
                    *(event.received_at for event in self.state.broker_events),
                    *(mark.knowledge_at for mark in self.state.marks),
                    *(item.recorded_at for item in self.state.stock_splits),
                    *(item.recorded_at for item in self.state.cash_dividends),
                    *(item.recorded_at for item in self.state.dividend_payments),
                    *(item.recorded_at for item in self.state.settlement_instructions),
                    *(item.recorded_at for item in self.state.settlement_confirmations),
                )
            ),
            default=self.now,
        )
        self.now = max(self.now, self.retained_knowledge)
        self.economic = self.now
        self.events: dict[str, EngineEvent] = {}
        self.causal_sources: dict[str, str] = {}
        self.sequence_parents: dict[str, str] = {}
        self.queue: list[tuple[datetime, str]] = []
        self.seen: set[str] = set()
        self.heads: dict[tuple[date, str], EngineEvent] = {}
        self.benchmarks: dict[datetime, EngineEvent] = {}
        self.done_sessions: set[date] = set()
        self.valued_sessions: set[date] = set()
        self.accepted: dict[date, set[str]] = {}
        self.targets: dict[str, DailyTarget] = {}
        self.trace: list[EngineTraceRow] = []
        self.valuations: list[ValuationRow] = []
        self.flows: list[ExternalFlowRow] = []
        self.benchmark_inputs: list[BenchmarkValuationInput] = []
        self.wealth: list[WealthPoint] = []
        self.daily_wealth: Decimal | None = Decimal(1)
        self.baseline_id: str | None = None
        self.terminal_id: str | None = None
        self.interval_id = canonical_id("scored-interval", self.spec.run_id)
        self.current = self.accounting.project(
            state=self.state, context=self._context("initial"), policy=self.spec.execution_policy
        )
        self.baseline_at = self.sessions[self.scored[0]].opens_at
        self.baseline_economic = self.baseline_at
        self.baseline_session = self.scored[0]

    def _context(
        self,
        event_id: str,
        approved: AccountSnapshot | None = None,
    ) -> AccountingContext:
        return AccountingContext(
            self.spec.run_id,
            ReductionPoint(self.frontier, self.sequence, self.now, self.stage),
            self.economic,
            event_id,
            self.mark_session,
            self.spec.instruments,
            approved,
            None if approved is None else self.spec.risk_policy.semantic_sha256,
        )

    @property
    def stage(self) -> int:
        return getattr(self, "_stage_number", 0)

    def _point(self, stage: int, *, economic: datetime | None = None) -> None:
        self.sequence += 1
        self._stage_number = stage
        if economic is not None:
            self.economic = economic

    def _project(self, event_id: str, stage: int = 4) -> AccountSnapshot:
        self._point(stage)
        self.current = self.accounting.project(
            state=self.state, context=self._context(event_id), policy=self.spec.execution_policy
        )
        return self.current.snapshot

    def _budget(self) -> None:
        if self.stop_requested is not None and self.stop_requested():
            raise _Stop("cancelled", "OWNER_CANCELLED")
        if monotonic() - self.started > self.spec.max_wall_seconds:
            raise _Stop("cancelled", "WALL_TIME_BUDGET_EXCEEDED")
        if self.processed > self.spec.max_events:
            raise _Stop("rejected", "EVENT_BUDGET_EXCEEDED")
        if self.output_bytes > self.spec.max_output_bytes:
            raise _Stop("rejected", "OUTPUT_BUDGET_EXCEEDED")

    def _trace(
        self,
        event_id: str,
        kind: str,
        source: str,
        before: AccountSnapshot,
        *,
        reasons: tuple[str, ...] = (),
        batch: DailyIntentBatch | None = None,
    ) -> None:
        after = self.current.snapshot
        quantities = (
            ()
            if batch is None
            else tuple((item.instrument_id, item.quantity) for item in batch.target.targets)
        )
        # Full provenance remains in the enclosing records. This independent
        # prefix digest contains only causal facts and observable account values.
        causal = content_digest(
            (
                source,
                kind,
                self.now,
                self.stage,
                quantities,
                reasons,
                tuple((p.instrument_id, p.quantity, p.cost_basis) for p in after.positions),
                tuple(
                    sorted(
                        (c.instrument_id, c.side, c.remaining_quantity, c.reserved_cash, c.state)
                        for c in after.commitments
                    )
                ),
                after.trade_date_cash,
                after.settled_cash,
                after.available_cash,
                after.trade_receivable,
                after.trade_payable,
                after.dividend_receivable,
                after.nav,
                after.halted,
                self.strategy_state.generation,
                self.strategy_state.previously_allocated,
                self.strategy_state.values,
            )
        )
        row = EngineTraceRow(
            event_id,
            ReductionPoint(self.frontier, self.sequence, self.now, self.stage),
            kind,
            source,
            before.semantic_sha256,
            after.semantic_sha256,
            self.state.semantic_sha256,
            () if batch is None else tuple(item.intent_id for item in batch.intents),
            quantities,
            reasons,
            causal,
        )
        self.trace.append(row)
        self.output_bytes += len(canonical_json_bytes(semantic_value(row)))
        self._budget()

    def _enqueue(self, event: EngineEvent) -> None:
        prior = self.events.get(event.event_id)
        if prior is not None:
            if prior != event:
                raise _Stop("rejected", "CONFLICTING_EVENT_ID")
            return
        if len(self.events) >= self.spec.max_events:
            raise _Stop("rejected", "EVENT_BUDGET_EXCEEDED")
        self.events[event.event_id] = event
        heapq.heappush(self.queue, (event.knowledge_at, event.event_id))

    def _scheduled(self, session: date, kind: str, at: datetime) -> None:
        signal = ScheduleSignal("personal-daily-calendar/1", session, kind)  # type: ignore[arg-type]
        event_id = canonical_id("engine-schedule", self.spec.calendar.calendar_id, session, kind)
        self._enqueue(self._internal(event_id, signal, at))

    def _internal(
        self,
        event_id: str,
        payload: ScheduleSignal | AccountingCommand,
        at: datetime,
        predecessors: tuple[str, ...] = (),
    ) -> EngineEvent:
        return EngineEvent(
            event_id,
            at,
            at,
            payload,
            ObservationProvenance(
                self.spec.data_class,
                "personal-engine-schedule/1",
                content_digest(payload),
                simulated_available_at=at,
                assumption_id="deterministic-calendar-or-due-command/1",
            ),
            predecessors,
        )

    def _due(self, events: tuple[DueAccountingEvent, ...]) -> None:
        for due in events:
            if (
                due.policy_sha256 != self.spec.execution_policy.semantic_sha256
                or due.due_at < self.now
            ):
                raise _Stop("failed", "INVALID_ACCOUNTING_DUE_EVENT")
            if due.parent_event_id not in self.seen:
                raise _Stop("failed", "ACCOUNTING_DUE_EVENT_PARENT_UNAVAILABLE")
            parent_source = self.causal_sources.get(due.parent_event_id)
            if parent_source is None:
                raise _Stop("failed", "ACCOUNTING_DUE_EVENT_CAUSAL_BINDING_UNAVAILABLE")
            self.causal_sources[due.event_id] = content_digest(
                (
                    "derived-accounting-event/1",
                    parent_source,
                    due.due_at,
                    type(due.command.payload).__name__,
                    self.spec.execution_policy.model_id,
                    self.spec.execution_policy.fee_per_share,
                    self.spec.execution_policy.slippage_bps,
                )
            )
            self._enqueue(
                self._internal(
                    due.event_id,
                    due.command,
                    due.due_at,
                    (due.parent_event_id,),
                )
            )

    def _apply(
        self,
        command: AccountingCommand,
        *,
        source: str,
        stage: int,
        approved: AccountSnapshot | None = None,
    ) -> AccountingTransition:
        before = self.current.snapshot
        self._point(stage)
        result = self.accounting.advance(
            state=self.state,
            command=command,
            context=self._context(command.command_id, approved),
            policy=self.spec.execution_policy,
        )
        if result.disposition == "rejected":
            self.current = self.accounting.project(
                state=self.state,
                context=self._context(command.command_id),
                policy=self.spec.execution_policy,
            )
            self._trace(
                command.command_id, "accounting_rejected", source, before, reasons=result.reasons
            )
            raise _Stop("failed", "ACCOUNTING_COMMAND_REJECTED")
        self.state, self.current = result.state, result
        self.seen.add(command.command_id)
        self.causal_sources[command.command_id] = source
        self._due(result.due_events)
        self._trace(
            command.command_id,
            type(command.payload).__name__,
            source,
            before,
            reasons=result.reasons,
        )
        return result

    def _admit(self) -> None:
        unique: dict[str, EngineEvent] = {}
        for event in self.inputs.events:
            if event.event_id in unique and unique[event.event_id] != event:
                raise _Stop("rejected", "CONFLICTING_EVENT_ID")
            unique[event.event_id] = event
        if content_digest(tuple(unique[key] for key in sorted(unique))) != self.spec.events_sha256:
            raise _Stop("rejected", "EVENT_MANIFEST_MISMATCH")
        if self.state.semantic_sha256 != self.spec.initial_state_sha256:
            raise _Stop("rejected", "INITIAL_STATE_IDENTITY_MISMATCH")
        if self.state.account_id != self.spec.account_id:
            raise _Stop("rejected", "ACCOUNT_IDENTITY_MISMATCH")
        if self.spec.risk_policy.policy_scope == "product" and self.state != AccountingState(
            self.spec.account_id
        ):
            raise _Stop("rejected", "PRODUCT_REQUIRES_EMPTY_INITIAL_ACCOUNT")
        if self.spec.execution_policy.fee_per_share > self.spec.risk_policy.fee_per_share:
            raise _Stop("rejected", "EXECUTION_FEE_EXCEEDS_RISK_BUDGET")
        if any(label not in self.sessions for label in self.expected):
            raise _Stop("rejected", "EVALUATION_OUTSIDE_CALENDAR")
        if self.labels.index(self.scored[-1]) + 1 == len(self.labels):
            raise _Stop("rejected", "NEXT_EXECUTION_SESSION_HORIZON_REQUIRED")
        streams: dict[str, dict[int, str]] = {}
        for event in unique.values():
            if event.provenance.data_class != self.spec.data_class:
                raise _Stop("rejected", "SOURCE_DATA_CLASS_MISMATCH")
            for parent in event.predecessor_ids:
                if parent not in unique or unique[parent].knowledge_at > event.knowledge_at:
                    raise _Stop("rejected", "MISSING_OR_FUTURE_PREDECESSOR")
            if event.sequence_scope is not None:
                assert event.source_sequence is not None
                stream = streams.setdefault(event.sequence_scope, {})
                if event.source_sequence in stream:
                    raise _Stop("rejected", "CONFLICTING_SOURCE_SEQUENCE")
                stream[event.source_sequence] = event.event_id
            payload = event.payload
            availability = (
                event.provenance.simulated_available_at
                if self.spec.availability_mode == "modeled"
                else event.provenance.observed_at
            )
            if availability is None or event.knowledge_at < availability:
                raise _Stop("rejected", "EVENT_PRECEDES_DECLARED_AVAILABILITY")
            if isinstance(payload, (DailyPrice, ExecutionObservation)):
                if dict(self.spec.instruments).get(payload.instrument_id) != payload.symbol:
                    raise _Stop("rejected", "EVENT_INSTRUMENT_OUTSIDE_UNIVERSE")
                if payload.session not in self.sessions:
                    raise _Stop("rejected", "EVENT_SESSION_OUTSIDE_CALENDAR")
            if isinstance(payload, DailyPrice):
                if event.economic_at != self.sessions[payload.session].closes_at:
                    raise _Stop("rejected", "DAILY_PRICE_ECONOMIC_BOUNDARY_MISMATCH")
                available = (
                    event.provenance.simulated_available_at
                    if self.spec.availability_mode == "modeled"
                    else event.provenance.observed_at
                )
                if available is None or event.knowledge_at < available:
                    raise _Stop("rejected", "PRICE_PRECEDES_DECLARED_AVAILABILITY")
                if self.spec.availability_mode == "modeled" and event.knowledge_at < (
                    modeled_daily_availability(payload.session)
                ):
                    raise _Stop("rejected", "DAILY_PRICE_PRECEDES_MODELED_2000")
            elif isinstance(payload, AccountingCommand) and isinstance(
                payload.payload, (InstallCommitment, ActivateCommitment)
            ):
                raise _Stop("rejected", "ENGINE_OWNED_COMMAND_IN_SOURCE_TAPE")
            elif isinstance(payload, ExecutionObservation):
                if (
                    payload.knowledge_at != event.knowledge_at
                    or payload.economic_at != event.economic_at
                    or payload.model_id != self.spec.execution_policy.model_id
                ):
                    raise _Stop("rejected", "EXECUTION_OBSERVATION_ENVELOPE_MISMATCH")
                if self.spec.execution_policy.model_id == "next-regular-open-proxy-v1" and (
                    payload.economic_at != self.sessions[payload.session].opens_at
                    or payload.basis != "raw_open"
                ):
                    raise _Stop("rejected", "EXECUTION_REQUIRES_EXACT_REGULAR_OPEN")
            self._enqueue(event)
        for stream in streams.values():
            previous: EngineEvent | None = None
            for number in sorted(stream):
                event = unique[stream[number]]
                if previous is not None and previous.knowledge_at > event.knowledge_at:
                    raise _Stop("rejected", "SOURCE_SEQUENCE_REVERSES_KNOWLEDGE")
                if previous is not None:
                    self.sequence_parents[event.event_id] = previous.event_id
                previous = event
        warmup = self.spec.evaluation.warmup_sessions
        if warmup:
            self.baseline_session = warmup[-1]
            self.baseline_economic = self.sessions[warmup[-1]].closes_at
            first_delivery: list[datetime] = []
            for instrument_id, _ in self.spec.instruments:
                deliveries = [
                    event.knowledge_at
                    for event in unique.values()
                    if isinstance(event.payload, DailyPrice)
                    and event.payload.session == warmup[-1]
                    and event.payload.instrument_id == instrument_id
                ]
                if not deliveries:
                    raise _Stop("rejected", "WARMUP_BASELINE_UNAVAILABLE")
                first_delivery.append(min(deliveries))
            self.baseline_at = max(modeled_daily_availability(warmup[-1]), *first_delivery)
            if self.baseline_at >= self.sessions[self.scored[0]].opens_at:
                raise _Stop("rejected", "WARMUP_BASELINE_NOT_KNOWN_BEFORE_SCORED_OPEN")
        if self.retained_knowledge > self.baseline_at:
            raise _Stop("rejected", "INITIAL_STATE_CONTAINS_POST_BASELINE_KNOWLEDGE")
        self._scheduled(self.baseline_session, "baseline", self.baseline_at)
        for label in self.scored:
            session = self.sessions[label]
            self._scheduled(label, "session_open", session.opens_at)
            self._scheduled(label, "session_close", session.closes_at)
            self._scheduled(label, "decision_due", modeled_daily_availability(label))
            next_label = self.labels[self.labels.index(label) + 1]
            self._scheduled(label, "missing_cutoff", _cutoff(next_label))

    def _ordered(self, events: list[EngineEvent]) -> list[EngineEvent]:
        remaining = {event.event_id: event for event in events}
        admitted = set(self.seen)
        result: list[EngineEvent] = []
        while remaining:
            ready = [
                event
                for event in remaining.values()
                if set(event.predecessor_ids) <= admitted
                and (
                    event.event_id not in self.sequence_parents
                    or self.sequence_parents[event.event_id] in admitted
                )
            ]
            if not ready:
                raise _Stop("rejected", "CYCLIC_OR_UNAVAILABLE_PREDECESSOR")
            event = min(
                ready,
                key=lambda item: (
                    item.economic_at,
                    _stage(item),
                    item.sequence_scope or "",
                    -1 if item.source_sequence is None else item.source_sequence,
                    self.causal_sources.get(item.event_id, item.event_id),
                ),
            )
            result.append(event)
            admitted.add(event.event_id)
            del remaining[event.event_id]
        return result

    def _complete(self, session: date) -> bool:
        return all(
            (session, instrument_id) in self.heads for instrument_id, _ in self.spec.instruments
        )

    def _mark(self, event: EngineEvent) -> None:
        payload = event.payload
        if isinstance(payload, DailyPrice):
            key = (payload.session, payload.instrument_id)
            prior = self.heads.get(key)
            if prior is None:
                if payload.revision != 1:
                    raise _Stop("rejected", "REVISION_PREDECESSOR_UNAVAILABLE")
            else:
                assert isinstance(prior.payload, DailyPrice)
                if (
                    payload.predecessor_revision_id != prior.event_id
                    or payload.revision != prior.payload.revision + 1
                    or prior.event_id not in event.predecessor_ids
                ):
                    raise _Stop("rejected", "REVISION_CHAIN_CONFLICT")
            self.heads[key] = event
            price, basis = payload.close_price, "raw_close"
        elif isinstance(payload, ExecutionObservation):
            price, basis = payload.price, "raw_execution"
        else:
            raise RuntimeError("mark requires price or execution observation")
        if self.now < self.baseline_at:
            return
        mark = CausalMark(
            canonical_id("causal-mark", event.event_id),
            payload.instrument_id,
            payload.symbol,
            price,
            payload.session,
            event.economic_at,
            event.knowledge_at,
            event.causal_sha256,
            basis=basis,  # type: ignore[arg-type]
        )
        self.economic = event.economic_at
        self._apply(AccountingCommand(mark.mark_id, mark), source=event.causal_sha256, stage=2)

    def _valuation(
        self,
        economic: datetime,
        session: date,
        roles: tuple[ValuationRole, ...],
        *,
        scored: bool = True,
        flow_id: str | None = None,
        row_id: str | None = None,
        paired: str | None = None,
        signed: Decimal = Decimal(0),
    ) -> ValuationRow:
        self.economic, self.mark_session = economic, session
        snapshot = self._project("valuation", 8)
        if "daily_close" in roles:
            later_financial_facts = (
                any(flow.effective_at > economic for flow in self.state.cash_flows)
                or any(
                    event.kind
                    in (BrokerOrderEventKind.EXECUTION, BrokerOrderEventKind.EXECUTION_CORRECTION)
                    and event.occurred_at > economic
                    for event in self.state.broker_events
                )
                or any(item.effective_at > economic for item in self.state.stock_splits)
                or any(item.effective_at > economic for item in self.state.cash_dividends)
            )
            if later_financial_facts:
                snapshot = replace(
                    snapshot,
                    nav=None,
                    market_value=None,
                    unrealized_pnl=None,
                    last_known_nav=snapshot.nav
                    if snapshot.nav is not None
                    else snapshot.last_known_nav,
                    valuation_reasons=tuple(
                        sorted(
                            set(
                                (
                                    *snapshot.valuation_reasons,
                                    "ECONOMIC_FACT_AFTER_VALUATION_BOUNDARY",
                                )
                            )
                        )
                    ),
                )
        if "pre_flow" in roles or "post_flow" in roles:
            exact_marks = {
                mark.instrument_id
                for mark in snapshot.marks
                if mark.economic_at == economic
                and mark.knowledge_at <= self.now
                and mark.quality == "current"
            }
            missing = tuple(
                sorted(
                    position.instrument_id
                    for position in snapshot.positions
                    if position.quantity and position.instrument_id not in exact_marks
                )
            )
            if missing:
                snapshot = replace(
                    snapshot,
                    nav=None,
                    market_value=None,
                    unrealized_pnl=None,
                    last_known_nav=snapshot.nav
                    if snapshot.nav is not None
                    else snapshot.last_known_nav,
                    valuation_reasons=tuple(
                        sorted(
                            set(
                                (
                                    *snapshot.valuation_reasons,
                                    *(
                                        "EXACT_FLOW_BOUNDARY_MARK_REQUIRED:" + item
                                        for item in missing
                                    ),
                                )
                            )
                        )
                    ),
                )
        row_id = row_id or canonical_id("valuation", self.spec.run_id, self.sequence, roles)
        row = ValuationRow(
            row_id,
            snapshot,
            economic,
            session,
            roles,
            scored,
            self.interval_id,
            flow_id,
            paired,
        )
        self.valuations.append(row)
        if scored:
            role = (
                "baseline"
                if "baseline" in roles
                else "pre_flow"
                if "pre_flow" in roles
                else ("post_flow" if "post_flow" in roles else "valuation")
            )
            self.wealth.append(
                WealthPoint(
                    row_id,
                    snapshot.point.reduction_sequence,
                    snapshot.nav,
                    signed_flow=signed if role == "post_flow" else Decimal(0),
                    flow_pair_id=flow_id if role in ("pre_flow", "post_flow") else None,
                    role=role,
                    reasons=snapshot.valuation_reasons,
                )
            )
        benchmark = self.benchmarks.get(economic)
        price = benchmark.payload if benchmark is not None else None
        assert price is None or isinstance(price, BenchmarkPrice)
        self.benchmark_inputs.append(
            BenchmarkValuationInput(
                row_id,
                "unavailable" if price is None else price.series_id,
                None if price is None else price.unit_price,
                content_digest(("missing-benchmark-boundary", economic))
                if benchmark is None
                else benchmark.causal_sha256,
                economic,
                self.now,
                "adjusted_total_return_units" if price is None else price.representation,
                ("BENCHMARK_PRICE_UNAVAILABLE_AT_EXACT_BOUNDARY",) if price is None else (),
            )
        )
        self.output_bytes += len(canonical_json_bytes(semantic_value(row)))
        self.output_bytes += len(canonical_json_bytes(semantic_value(self.benchmark_inputs[-1])))
        self._budget()
        return row

    def _flow(self, command: AccountingCommand, source: str, *, initial: bool = False) -> None:
        flow = command.payload
        assert isinstance(flow, LedgerCashFlow)
        self.mark_session = flow.effective_at.astimezone(ZoneInfo("America/New_York")).date()
        if any(item.flow.cash_flow_id == flow.cash_flow_id for item in self.flows):
            self._apply(command, source=source, stage=1)
            return
        pre_id = canonical_id("pre-flow", self.spec.run_id, flow.cash_flow_id)
        post_id = canonical_id("post-flow", self.spec.run_id, flow.cash_flow_id)
        self._valuation(
            flow.effective_at,
            self.mark_session,
            ("pre_flow",),
            scored=not initial,
            flow_id=flow.cash_flow_id,
            row_id=pre_id,
            paired=post_id,
        )
        result = self._apply(command, source=source, stage=1)
        signed = (
            flow.amount if flow.kind is CashFlowKind.CONTRIBUTION else flow.amount.copy_negate()
        )
        roles: tuple[ValuationRole, ...] = ("post_flow", "baseline") if initial else ("post_flow",)
        post = self._valuation(
            flow.effective_at,
            self.mark_session,
            roles,
            flow_id=flow.cash_flow_id,
            row_id=post_id,
            paired=pre_id,
            signed=signed,
        )
        self.flows.append(
            ExternalFlowRow(
                flow,
                signed,
                result.snapshot.point.reduction_sequence,
                pre_id,
                post_id,
                "initial_capital" if initial else "external_flow",
                post.snapshot.journal_sha256,
            )
        )
        if initial:
            self.baseline_id = post.row_id

    def _baseline(self) -> None:
        if self.baseline_id is not None:
            return
        self.economic, self.mark_session = self.baseline_economic, self.baseline_session
        if self.spec.initial_cash:
            flow = create_cash_flow(
                kind=CashFlowKind.CONTRIBUTION,
                currency="USD",
                amount=self.spec.initial_cash,
                effective_at=self.baseline_economic,
                recorded_at=self.now,
                external_reference=canonical_id("initial-capital", self.spec.run_id),
            )
            self._flow(
                AccountingCommand(flow.cash_flow_id, flow),
                content_digest(("initial-capital", flow.amount)),
                initial=True,
            )
        else:
            self.baseline_id = self._valuation(
                self.baseline_economic, self.baseline_session, ("baseline",)
            ).row_id
        self.strategy_state = self.strategy.initialize(
            configuration=self.spec.strategy_configuration,
            initial_snapshot=self.current.snapshot,
        )
        if self.current.snapshot.nav is None or self.current.snapshot.nav <= 0:
            raise _Stop("rejected", "POSITIVE_CAUSAL_BASELINE_REQUIRED")

    def _loss(self) -> tuple[Decimal | None, Decimal | None]:
        if not self.wealth:
            return None, None
        snapshot = self.current.snapshot
        points = (
            *self.wealth,
            WealthPoint(
                "risk-" + str(self.sequence),
                self.sequence + 1,
                snapshot.nav,
                reasons=snapshot.valuation_reasons,
            ),
        )
        value = derive_wealth_path(points)[-1]
        if value.wealth is None or self.daily_wealth is None:
            return None, value.drawdown
        with localcontext(derived_context()):
            return value.wealth / self.daily_wealth - 1, value.drawdown

    def _evidence(
        self, batch: DailyIntentBatch, phase: Literal["decision", "activation"]
    ) -> DailyRiskEvidence:
        daily_return, drawdown = self._loss()
        trigger = batch.target.trigger
        return DailyRiskEvidence(
            self.current.snapshot.semantic_sha256,
            phase,
            self.now,
            trigger.source_session,
            trigger.execution_session,
            next(pin for pin in self.spec.pins if pin.name == "engine"),
            daily_return,
            drawdown,
            tuple(sorted(self.accepted.get(trigger.execution_session, set()))),
            self._complete(trigger.source_session),
            not self.state.halted,
            True,
            self.now < batch.target.expires_at,
            True,
            self.requests.permits(
                self.now, len(batch.intents) if phase == "decision" else 0, low_priority=True
            ),
            True,
        )

    def _install(self, batch: DailyIntentBatch) -> None:
        before = self.current.snapshot
        decision = evaluate_daily_risk(
            self.spec.risk_policy,
            before,
            batch,
            self._evidence(batch, "decision"),
            self.now,
        )
        if not decision.approved or not batch.intents:
            self._trace(
                batch.target.trigger.trigger_id,
                "risk_approved" if decision.approved else "risk_rejected",
                batch.target.trigger.source_sha256,
                before,
                reasons=decision.reasons,
                batch=batch,
            )
            return
        state = self.state
        pending_results: list[AccountingTransition] = []
        holds = dict(decision.reserved_cash_by_intent)
        share_holds = dict(decision.reserved_shares_by_intent)
        for intent in batch.intents:
            self._point(6)
            submission = create_order_submission(
                intent=intent,
                risk_decision_id=decision.semantic_sha256,
                submission_attempt_id=canonical_id("model-attempt", intent.intent_id),
                submitted_at=self.now,
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
                share_holds.get(intent.intent_id, Decimal(0)),
                mul(
                    intent.reference_price,
                    add(Decimal(1), self.spec.risk_policy.adverse_reserve_fraction),
                ),
                mul(intent.quantity, self.spec.risk_policy.fee_per_share),
                batch.target.trigger.source_session,
                batch.target.trigger.execution_session,
                self.sequence,
                batch.target.not_before,
                batch.target.expires_at,
                decision.policy_sha256,
                before.semantic_sha256,
            )
            command = AccountingCommand(
                commitment.commitment_id, InstallCommitment(submission, commitment)
            )
            result = self.accounting.advance(
                state=state,
                command=command,
                context=self._context(command.command_id, before),
                policy=self.spec.execution_policy,
            )
            if result.disposition != "applied":
                self._project("atomic-batch-rollback", 6)
                self._trace(
                    batch.batch_id,
                    "batch_install_rolled_back",
                    batch.target.trigger.source_sha256,
                    before,
                    reasons=result.reasons or ("INSTALL_NOT_APPLIED",),
                    batch=batch,
                )
                return
            state = result.state
            pending_results.append(result)
        self.state, self.current = state, pending_results[-1]
        for result in pending_results:
            self._due(result.due_events)
        self.accepted.setdefault(batch.target.trigger.execution_session, set()).update(
            item.intent_id for item in batch.intents
        )
        for intent in batch.intents:
            self.targets[intent.intent_id] = batch.target
        self._trace(
            batch.batch_id,
            "batch_installed",
            batch.target.trigger.source_sha256,
            before,
            batch=batch,
        )

    def _decision(
        self, source_session: date, event_id: str, kind: Literal["complete_market", "timer"]
    ) -> None:
        if source_session not in self.scored or self.baseline_id is None:
            return
        execution = self.labels[self.labels.index(source_session) + 1]
        if self.now < modeled_daily_availability(source_session) or self.now >= _cutoff(execution):
            return
        if not self._complete(source_session):
            return
        self.mark_session = source_session
        self.economic = self.sessions[source_session].closes_at
        account = self._project(event_id, 5)
        visible = tuple(
            (key, self.heads[key].causal_sha256)
            for key in sorted(self.heads)
            if key[0] <= source_session
        )
        trigger = DailyTrigger(
            event_id,
            source_session,
            execution,
            self.now,
            kind,
            content_digest(visible),
            self.sequence,
        )
        expected = tuple(label for label in self.expected if label <= source_session)
        history: list[tuple[date, tuple[tuple[str, Decimal | None], ...]]] = []
        for label in expected:
            values: list[tuple[str, Decimal | None]] = []
            for instrument_id, _ in self.spec.instruments:
                event = self.heads.get((label, instrument_id))
                price = None
                if event is not None:
                    assert isinstance(event.payload, DailyPrice)
                    price = (
                        event.payload.adjusted_close
                        if self.spec.feature_price_basis == "adjusted_close"
                        else event.payload.close_price
                    )
                values.append((instrument_id, price))
            history.append((label, tuple(values)))
        context = DailyStrategyContext(
            trigger,
            account,
            self.strategy_state,
            self.spec.strategy_configuration,
            self.spec.instruments,
            tuple(history),
            expected,
            self.scored.index(source_session),
            self.sessions[execution].opens_at,
            self.sessions[execution].closes_at,
        )
        transition = self.strategy.on_decision(context)
        if (
            transition.state.generation != self.strategy_state.generation + 1
            or transition.state.predecessor_sha256 != self.strategy_state.semantic_sha256
        ):
            raise _Stop("failed", "STRATEGY_STATE_TRANSITION_UNBOUND")
        self.strategy_state = transition.state
        target = transition.target
        if target is None:
            self._trace(
                event_id,
                "strategy_no_target",
                trigger.source_sha256,
                account,
                reasons=transition.reasons,
            )
            return
        if (
            target.trigger != trigger
            or target.configuration_sha256 != content_digest(context.configuration)
            or target.not_before != context.not_before
            or target.expires_at != context.expires_at
            or {item.instrument_id: item.symbol for item in target.targets}
            != dict(self.spec.instruments)
            or not target.full_snapshot
        ):
            raise _Stop("failed", "STRATEGY_TARGET_OUTSIDE_FROZEN_CONTEXT")
        self._point(6)
        # Conversion/risk use the exact callback snapshot. The next callback is
        # projected again after the complete installation microcycle.
        batch = daily_target_to_intents(target, account, strategy_pin=self.spec.strategy)
        self._install(batch)

    def _activation_risk(self, observations: list[EngineEvent]) -> None:
        eligible = tuple(
            c
            for c in self.state.commitments
            if c.state in ("active", "working", "partial")
            and c.activation_frontier is not None
            and c.activation_frontier < self.frontier
            and any(
                isinstance(e.payload, ExecutionObservation)
                and e.payload.session == c.execution_session
                and c.activated_at is not None
                and c.activated_at < e.economic_at
                and c.not_before <= e.economic_at < c.expires_at
                for e in observations
            )
        )
        groups: dict[str, list[Commitment]] = {}
        for commitment in eligible:
            target = self.targets.get(commitment.intent_id)
            if target is None:
                raise _Stop("failed", "ACTIVATION_TARGET_BINDING_UNAVAILABLE")
            groups.setdefault(target.target_id, []).append(commitment)
        for commitments in groups.values():
            target = self.targets[commitments[0].intent_id]
            self.mark_session = target.trigger.execution_session
            account = self._project("execution-risk", 3)
            originals = {item.intent.intent_id: item.intent for item in self.state.submissions}
            intents = tuple(
                replace(originals[c.intent_id], quantity=c.remaining_quantity) for c in commitments
            )
            batch = DailyIntentBatch(
                canonical_id("activation-batch", target.target_id, self.sequence),
                target,
                account.semantic_sha256,
                intents,
            )
            decision = evaluate_daily_risk(
                self.spec.risk_policy, account, batch, self._evidence(batch, "activation"), self.now
            )
            self._trace(
                batch.batch_id,
                "activation_risk_approved" if decision.approved else "activation_risk_rejected",
                target.trigger.source_sha256,
                account,
                reasons=decision.reasons,
                batch=batch,
            )
            if not decision.approved:
                self._halt("CURRENT_EXECUTION_RISK_REJECTED")

    def _halt(self, reason: str) -> None:
        if self.state.halted:
            return
        command = AccountingCommand(
            canonical_id("engine-halt", self.now, reason), ControlCommand(True, reason)
        )
        self._apply(command, source=content_digest(reason), stage=0)

    def _frontier(self, events: list[EngineEvent]) -> None:
        ordered = self._ordered(events)
        observations = [
            event for event in ordered if isinstance(event.payload, ExecutionObservation)
        ]
        if len({event.economic_at for event in observations}) > 1:
            raise _Stop("rejected", "AMBIGUOUS_EXECUTION_ECONOMIC_FRONTIER")
        # Every observation's open-only mark is in the account before execution
        # risk or any observation, independent of input symbol ordering.
        risk_checked = False
        observed_ids = {
            (item.payload.session, item.payload.instrument_id)
            for item in observations
            if isinstance(item.payload, ExecutionObservation)
        }
        for event in ordered:
            if (
                isinstance(event.payload, ScheduleSignal)
                and event.payload.kind == "session_open"
                and any(
                    c.state != "terminal"
                    and c.execution_session == event.payload.source_session
                    and (c.execution_session, c.instrument_id) not in observed_ids
                    for c in self.state.commitments
                )
            ):
                self._halt("MISSING_EXECUTION_OPEN_OBSERVATION")
        for event in ordered:
            self._budget()
            self.processed += 1
            self.seen.add(event.event_id)
            payload = event.payload
            self.economic = event.economic_at
            if isinstance(payload, DailyPrice):
                self.mark_session = payload.session
                self._mark(event)
            elif isinstance(payload, BenchmarkPrice):
                previous = self.benchmarks.get(event.economic_at)
                if (
                    previous is not None
                    and previous.payload != event.payload
                    and previous.event_id not in event.predecessor_ids
                ):
                    raise _Stop("rejected", "CONFLICTING_BENCHMARK_BOUNDARY")
                self.benchmarks[event.economic_at] = event
            elif isinstance(payload, ExecutionObservation):
                if self.now < self.baseline_at:
                    continue
                if not risk_checked:
                    for observation in observations:
                        self.mark_session = observation.payload.session  # type: ignore[union-attr]
                        self._mark(observation)
                    if self.now == self.baseline_at:
                        self._baseline()
                    self._activation_risk(observations)
                    risk_checked = True
                self.economic = event.economic_at
                self.mark_session = payload.session
                self._apply(
                    AccountingCommand(payload.observation_id, payload),
                    source=event.causal_sha256,
                    stage=3,
                )
            elif isinstance(payload, AccountingCommand):
                if isinstance(payload.payload, CausalMark):
                    self.mark_session = payload.payload.session
                if isinstance(payload.payload, OrderCancelRequest):
                    self.requests.record(self.now, low_priority=False)
                if (
                    self.baseline_id is None
                    and self.now == self.baseline_at
                    and not isinstance(payload.payload, CausalMark)
                ):
                    self._baseline()
                if self.baseline_id is None and not (
                    self.now == self.baseline_at and isinstance(payload.payload, CausalMark)
                ):
                    raise _Stop("rejected", "ACCOUNTING_FACT_PRECEDES_SCORED_BASELINE")
                if isinstance(payload.payload, LedgerCashFlow):
                    self._flow(
                        payload, self.causal_sources.get(event.event_id, event.causal_sha256)
                    )
                else:
                    self._apply(
                        payload,
                        source=self.causal_sources.get(event.event_id, event.causal_sha256),
                        stage=_stage(event),
                    )
        # Accounting may schedule a correction settlement at this receipt
        # instant. Drain it in this frontier before any callback observes state.
        while self.queue and self.queue[0][0] == self.now:
            _, due_id = heapq.heappop(self.queue)
            due_event = self.events[due_id]
            if due_id in self.seen:
                continue
            if not isinstance(due_event.payload, AccountingCommand):
                raise _Stop("failed", "NONACCOUNTING_SAME_FRONTIER_DUE_EVENT")
            self.processed += 1
            self._budget()
            self.seen.add(due_id)
            self.economic = due_event.economic_at
            self._apply(due_event.payload, source=self.causal_sources[due_id], stage=1)
        signals = [
            (event, event.payload) for event in ordered if isinstance(event.payload, ScheduleSignal)
        ]
        for event, signal in signals:
            if signal.kind == "baseline":
                self._baseline()
            elif signal.kind == "session_close":
                self.economic = self.sessions[signal.source_session].closes_at
                self.mark_session = signal.source_session
                for commitment in tuple(self.state.commitments):
                    if (
                        commitment.execution_session == signal.source_session
                        and commitment.state in ("approved_unsent", "active", "working", "partial")
                        and not self.state.halted
                    ):
                        disposition = ModelDisposition(
                            commitment.commitment_id, "day_expired", event.event_id
                        )
                        self._apply(
                            AccountingCommand(
                                canonical_id("day-expiry", commitment.commitment_id), disposition
                            ),
                            source=event.causal_sha256,
                            stage=1,
                        )
            elif (
                signal.kind == "missing_cutoff" and signal.source_session not in self.done_sessions
            ):
                self.done_sessions.add(signal.source_session)
                self._halt("DAILY_INPUT_MISSING_AT_0900_CUTOFF")
        if self.baseline_id is None:
            return
        candidates = {
            event.payload.session for event in ordered if isinstance(event.payload, DailyPrice)
        }
        candidates.update(
            signal.source_session for _, signal in signals if signal.kind == "decision_due"
        )
        for source in sorted(candidates):
            if (
                source in self.scored
                and source not in self.done_sessions
                and self._complete(source)
            ):
                execution = self.labels[self.labels.index(source) + 1]
                if modeled_daily_availability(source) <= self.now < _cutoff(execution):
                    self.done_sessions.add(source)
                    self._decision(
                        source, canonical_id("daily-decision", source), "complete_market"
                    )
        for event, signal in sorted(signals, key=lambda pair: (pair[1].sequence, pair[0].event_id)):
            if signal.kind == "timer" and signal.source_session not in self.done_sessions:
                execution = self.labels[self.labels.index(signal.source_session) + 1]
                if self._complete(signal.source_session) and modeled_daily_availability(
                    signal.source_session
                ) <= self.now < _cutoff(execution):
                    self.done_sessions.add(signal.source_session)
                self._decision(signal.source_session, event.event_id, "timer")
        for commitment in tuple(self.state.commitments):
            if commitment.state == "approved_unsent" and not self.state.halted:
                self.economic = self.now
                if not self.requests.permits(self.now, 1, low_priority=True):
                    self._halt("SIMULATED_REQUEST_CAPACITY_EXHAUSTED")
                    break
                self.requests.record(self.now, low_priority=True)
                self._apply(
                    AccountingCommand(
                        canonical_id("activate", commitment.commitment_id),
                        ActivateCommitment(commitment.commitment_id),
                    ),
                    source=content_digest(
                        ("activate", commitment.instrument_id, commitment.remaining_quantity)
                    ),
                    stage=7,
                )
        for source in sorted(self.done_sessions - self.valued_sessions):
            self.valued_sessions.add(source)
            # An opening price is never promoted to a closing valuation. Retain
            # it only as an explicitly unavailable estimate when close is absent.
            for instrument_id, symbol in self.spec.instruments:
                if (source, instrument_id) not in self.heads:
                    prior = next(
                        (
                            m
                            for m in self.current.snapshot.marks
                            if m.instrument_id == instrument_id
                        ),
                        None,
                    )
                    if prior is not None:
                        mark = CausalMark(
                            canonical_id("unavailable-close", source, instrument_id),
                            instrument_id,
                            symbol,
                            prior.price,
                            source,
                            self.sessions[source].closes_at,
                            self.now,
                            content_digest(("missing-close", source, instrument_id)),
                            quality="unavailable",
                            basis="raw_close",
                        )
                        self.economic = mark.economic_at
                        self.mark_session = source
                        self._apply(
                            AccountingCommand(mark.mark_id, mark),
                            source=mark.source_sha256,
                            stage=2,
                        )
            terminal = source == self.scored[-1]
            roles: tuple[ValuationRole, ...] = (
                ("daily_close", "terminal") if terminal else ("daily_close",)
            )
            row = self._valuation(self.sessions[source].closes_at, source, roles)
            self.daily_wealth = derive_wealth_path(tuple(self.wealth))[-1].wealth
            if terminal:
                self.terminal_id = row.row_id

    def run(self) -> EngineResult:
        status: Literal["completed", "cancelled", "failed", "rejected"] = "completed"
        reasons: tuple[str, ...] = ()
        try:
            self._admit()
            while self.queue and self.terminal_id is None:
                self._budget()
                instant = self.queue[0][0]
                self.now = instant
                self.frontier += 1
                events: list[EngineEvent] = []
                while self.queue and self.queue[0][0] == instant:
                    _, event_id = heapq.heappop(self.queue)
                    events.append(self.events[event_id])
                self._frontier(events)
            if self.terminal_id is None:
                raise _Stop("failed", "TERMINAL_VALUATION_UNAVAILABLE")
        except _Stop as stop:
            status, reasons = stop.status, (stop.reason,)
        except (ValueError, ArithmeticError):
            # Port/strategy failures are bounded metadata, never provider payloads.
            status, reasons = "failed", ("INVALID_CAUSAL_TRANSITION",)
        self.current = self.accounting.project(
            state=self.state,
            context=self._context("final"),
            policy=self.spec.execution_policy,
        )
        result = EngineResult(
            self.spec,
            status,
            tuple(self.trace),
            self.state,
            self.current.snapshot,
            self.strategy_state,
            tuple(self.valuations),
            tuple(self.flows),
            self.current.executions,
            self.current.fifo_matches,
            self.current.journal_entries,
            tuple(self.benchmark_inputs),
            ScoredInterval(
                self.interval_id,
                self.spec.evaluation.fold_id,
                self.baseline_id or "unavailable-baseline",
                self.terminal_id or "unavailable-terminal",
                self.scored,
                self.spec.evaluation.warmup_sessions,
                content_digest(self.spec.calendar),
            ),
            reasons,
        )
        if len(canonical_json_bytes(semantic_value(result))) > self.spec.max_output_bytes:
            return replace(result, status="rejected", reasons=("OUTPUT_BUDGET_EXCEEDED",))
        return result


def run_causal_engine(
    inputs: EngineInputs,
    *,
    accounting: ExecutionAccountingPort,
    strategy: DailyStrategy,
    stop_requested: Callable[[], bool] | None = None,
) -> EngineResult:
    """Run one bounded independent fold using only admitted causal facts."""
    return _Engine(inputs, accounting, strategy, stop_requested).run()
