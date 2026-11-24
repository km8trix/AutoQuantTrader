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
from math import ceil
from time import monotonic
from typing import Literal
from zoneinfo import ZoneInfo

from packages.application.account_reconciliation import (
    check_reconciliation_candidate,
    derive_reconciliation_application,
    plan_reconciliation_facts,
    reconciliation_fact_effective_at,
    reconciliation_ready_facts,
)
from packages.application.daily_commitment_install import prepare_daily_commitments
from packages.application.personal_codec import encode_record
from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingState,
    AccountingTransition,
    AccountSnapshot,
    ActivateCommitment,
    ActivateRuntimeCommitments,
    Commitment,
    ControlCommand,
    DueAccountingEvent,
    ExecutionAccountingPort,
    ExecutionObservation,
    InstallCommitment,
    ModelDisposition,
    RegisterVenueSubmission,
    ReleaseRuntimeUnsent,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import (
    ClosedEngineFrontier,
    ContinuousDecision,
    ContinuousEngineInputs,
    ContinuousEngineSpec,
    ContinuousRiskEvidencePort,
)
from packages.domain.continuous_reconciliation_contracts import ContinuousReconciliationBatch
from packages.domain.continuous_runtime_action import ContinuousRuntimeAction
from packages.domain.daily_risk import evaluate_daily_risk
from packages.domain.daily_runtime_contracts import DailyRuntimeRiskEvidence
from packages.domain.engine_contracts import (
    BenchmarkPrice,
    DailyIntentBatch,
    DailyPrice,
    DailyRiskDecision,
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
)
from packages.domain.personal_contracts import (
    CausalMark,
    ReductionPoint,
    content_digest,
    require_utc,
    semantic_value,
)
from packages.domain.portfolio import daily_target_to_intents
from packages.domain.reconciliation_application_contracts import AppliedReconciliationBatch
from packages.domain.reconciliation_contracts import FactApplication
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


def continuous_request_budget_available(
    rows: tuple[tuple[datetime, bool], ...],
    *,
    at: datetime,
    count: int,
    low_priority: bool,
) -> bool:
    """Read the existing engine's modeled request budget from its exact callback rows.

    This is not an external provider quota or a transport-reservation proof.
    Original row times are retained and the copied budget is never published.
    """
    require_utc(at, "modeled request budget check")
    if type(rows) is not tuple or len(rows) > 20 or type(count) is not int or not 0 <= count <= 20:
        raise ValueError("modeled request inventory or requested count exceeds its bound")
    if type(low_priority) is not bool:
        raise ValueError("modeled request priority must be explicit")
    previous = None
    for row in rows:
        if type(row) is not tuple or len(row) != 2 or type(row[1]) is not bool:
            raise ValueError("modeled request rows require exact immutable values")
        require_utc(row[0], "modeled request time")
        if row[0] > at or (previous is not None and row[0] < previous):
            raise ValueError("modeled request rows reverse time or contain future knowledge")
        previous = row[0]
    budget = _SimulatedRequests()
    budget.rows = list(rows)
    return budget.permits(at, count, low_priority=low_priority)


def _cutoff(session: date) -> datetime:
    return datetime.combine(session, time(9), ZoneInfo("America/New_York")).astimezone(UTC)


def _stage(event: EngineEvent) -> int:
    payload = event.payload
    if isinstance(payload, AccountingCommand):
        return 0 if isinstance(payload.payload, ControlCommand) else 1
    if isinstance(payload, ContinuousReconciliationBatch):
        return 1
    if isinstance(payload, (DailyPrice, BenchmarkPrice)):
        return 2
    if isinstance(payload, ExecutionObservation):
        return 3
    return 5


class _Engine:
    def __init__(
        self,
        inputs: EngineInputs | ContinuousEngineInputs,
        accounting: ExecutionAccountingPort,
        strategy: DailyStrategy,
        stop_requested: Callable[[], bool] | None,
        runtime_evidence: ContinuousRiskEvidencePort | None = None,
    ) -> None:
        self.inputs, self.spec = inputs, inputs.spec
        self.accounting, self.strategy, self.stop_requested = accounting, strategy, stop_requested
        self.runtime_evidence = runtime_evidence
        self.continuous = isinstance(inputs, ContinuousEngineInputs)
        self.closed_source_frontiers: dict[str, str] = {}
        self.runtime_decisions: list[ContinuousDecision] = []
        self.application_batches: list[AppliedReconciliationBatch] = []
        self._last_apply_context: AccountingContext | None = None
        self.started = monotonic()
        self._wall_allowance_ns = self.spec.max_wall_seconds * 10**9
        self._closure_status = "unadmitted"
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
        if isinstance(self.spec, ContinuousEngineSpec):
            self.now = self.spec.initialized_at
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
        if isinstance(self.spec, ContinuousEngineSpec):
            self.baseline_at = self.baseline_economic = self.spec.initialized_at
            self.baseline_session = self.spec.initialized_at.astimezone(
                ZoneInfo("America/New_York")
            ).date()

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
        if self._remaining_wall_ns() < 0:
            raise _Stop("cancelled", "WALL_TIME_BUDGET_EXCEEDED")
        if self.processed > self.spec.max_events:
            raise _Stop("rejected", "EVENT_BUDGET_EXCEEDED")
        if self.output_bytes > self.spec.max_output_bytes:
            raise _Stop("rejected", "OUTPUT_BUDGET_EXCEEDED")

    def _remaining_wall_ns(self) -> int:
        # Round consumption upward. A restore can never replenish the retained
        # finite-run budget, including time spent restoring/projecting state.
        return self._wall_allowance_ns - ceil(max(0.0, monotonic() - self.started) * 10**9)

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
        reject_stops: bool = True,
    ) -> AccountingTransition:
        before = self.current.snapshot
        self._point(stage)
        context = self._context(command.command_id, approved)
        self._last_apply_context = context
        result = self.accounting.advance(
            state=self.state,
            command=command,
            context=context,
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
            if reject_stops:
                raise _Stop("failed", "ACCOUNTING_COMMAND_REJECTED")
            return result
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
        if self._closure_status != "unadmitted":
            raise _Stop("failed", "ENGINE_ALREADY_ADMITTED")
        self._closure_status = "admitting"
        if isinstance(self.inputs, ContinuousEngineInputs):
            self._admit_continuous()
            self._closure_status = "closed"
            return
        assert not isinstance(self.spec, ContinuousEngineSpec)
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
            elif isinstance(payload, ContinuousReconciliationBatch):
                raise _Stop("rejected", "CONTINUOUS_RECONCILIATION_NOT_A_FINITE_SOURCE")
            elif isinstance(payload, AccountingCommand) and isinstance(
                payload.payload,
                (
                    InstallCommitment,
                    ActivateCommitment,
                    ActivateRuntimeCommitments,
                    RegisterVenueSubmission,
                    ReleaseRuntimeUnsent,
                ),
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
        self._closure_status = "closed"

    def _admit_continuous(self) -> None:
        """Initialize once from known warmup rows, without a future tape."""
        assert isinstance(self.inputs, ContinuousEngineInputs)
        spec = self.inputs.spec
        if spec.execution_policy.fee_per_share > spec.risk_policy.fee_per_share:
            raise _Stop("rejected", "EXECUTION_FEE_EXCEEDS_RISK_BUDGET")
        for event in self.inputs.bootstrap_events:
            if not isinstance(event.payload, (DailyPrice, BenchmarkPrice)):
                raise _Stop("rejected", "CONTINUOUS_BOOTSTRAP_REQUIRES_MARKET_HISTORY")
            if isinstance(event.payload, DailyPrice) and (
                event.payload.session not in spec.window.warmup_sessions
            ):
                raise _Stop("rejected", "BOOTSTRAP_PRICE_OUTSIDE_WARMUP")
        self._admit_continuous_events(
            self.inputs.bootstrap_events, at=spec.initialized_at, bootstrap=True
        )
        self._scheduled(self.baseline_session, "baseline", self.baseline_at)
        for label in self.scored:
            session = self.sessions[label]
            for kind, at in (
                ("session_open", session.opens_at),
                ("session_close", session.closes_at),
                ("decision_due", modeled_daily_availability(label)),
            ):
                if at > spec.initialized_at:
                    self._scheduled(label, kind, at)
            following = self.labels[self.labels.index(label) + 1]
            self._scheduled(label, "missing_cutoff", _cutoff(following))

    def _admit_continuous_events(
        self,
        events: tuple[EngineEvent, ...],
        *,
        at: datetime,
        bootstrap: bool = False,
    ) -> None:
        remaining: dict[str, EngineEvent] = {}
        for event in events:
            if event.event_id in self.events:
                self._admit_continuous_event(event, at=at)
            else:
                remaining[event.event_id] = event
        while remaining:
            self._budget()
            first_sequences: dict[str, int] = {}
            for event in remaining.values():
                if event.sequence_scope is not None:
                    assert event.source_sequence is not None
                    first_sequences[event.sequence_scope] = min(
                        first_sequences.get(event.sequence_scope, event.source_sequence),
                        event.source_sequence,
                    )
            ready = sorted(
                (
                    event
                    for event in remaining.values()
                    if set(event.predecessor_ids) <= set(self.events)
                    and (
                        event.sequence_scope is None
                        or event.source_sequence == first_sequences[event.sequence_scope]
                    )
                ),
                key=lambda event: (
                    event.sequence_scope or "",
                    event.source_sequence or 0,
                    event.event_id,
                ),
            )
            if not ready:
                raise ValueError("closed frontier has missing or cyclic predecessors")
            for event in ready:
                # Earlier bootstrap knowledge is retained exactly. A newly
                # delivered frontier still requires this actual close time.
                if bootstrap and event.knowledge_at > at:
                    raise ValueError("bootstrap contains future knowledge")
                self._admit_continuous_event(event, at=event.knowledge_at if bootstrap else at)
                del remaining[event.event_id]

    def _admit_continuous_event(self, event: EngineEvent, *, at: datetime) -> None:
        """Validate a newly closed observation, preserving receipt provenance."""
        assert isinstance(self.spec, ContinuousEngineSpec)
        prior = self.events.get(event.event_id)
        if prior is not None:
            if prior != event:
                raise _Stop("rejected", "CONFLICTING_EVENT_ID")
            return
        if event.knowledge_at != at:
            raise _Stop("rejected", "NEW_EVENT_REQUIRES_CURRENT_CLOSED_FRONTIER")
        if event.provenance.data_class != self.spec.data_class:
            raise _Stop("rejected", "SOURCE_DATA_CLASS_MISMATCH")
        availability = (
            event.provenance.observed_at
            if self.spec.availability_mode == "recorded"
            else event.provenance.simulated_available_at
        )
        if availability is None or availability > at:
            raise _Stop("rejected", "EVENT_PRECEDES_DECLARED_AVAILABILITY")
        if self.spec.availability_mode == "recorded" and (
            event.provenance.raw_sha256 is None
            or event.provenance.simulated_available_at is not None
        ):
            raise _Stop("rejected", "OBSERVED_SOURCE_REQUIRES_RETAINED_CAPTURE")
        payload = event.payload
        if isinstance(payload, (ExecutionObservation, ScheduleSignal)) or (
            isinstance(payload, AccountingCommand)
            and isinstance(
                payload.payload,
                (
                    InstallCommitment,
                    ActivateCommitment,
                    ActivateRuntimeCommitments,
                    ModelDisposition,
                    RegisterVenueSubmission,
                    ReleaseRuntimeUnsent,
                ),
            )
        ):
            raise _Stop("rejected", "ENGINE_OR_VENUE_OWNED_COMMAND_IN_SOURCE")
        if isinstance(payload, ContinuousReconciliationBatch) and (
            payload.scope.account_id != self.spec.account_id
            or payload.scope.binding_sha256 != self.spec.account_binding_sha256
            or payload.scope.environment != self.spec.environment
            or any(page.received_at > at for page in payload.source_receipts)
        ):
            raise _Stop("rejected", "RECONCILIATION_BATCH_SCOPE_OR_TIME_DIFFERS")
        if isinstance(payload, DailyPrice):
            if dict(self.spec.instruments).get(payload.instrument_id) != payload.symbol:
                raise _Stop("rejected", "EVENT_INSTRUMENT_OUTSIDE_UNIVERSE")
            if payload.session not in self.sessions:
                raise _Stop("rejected", "EVENT_SESSION_OUTSIDE_CALENDAR")
            if event.economic_at != self.sessions[payload.session].closes_at:
                raise _Stop("rejected", "DAILY_PRICE_ECONOMIC_BOUNDARY_MISMATCH")
        if any(
            parent not in self.events or self.events[parent].knowledge_at > at
            for parent in event.predecessor_ids
        ):
            raise _Stop("rejected", "MISSING_OR_FUTURE_PREDECESSOR")
        if event.sequence_scope is not None:
            stream = sorted(
                (
                    previous
                    for previous in self.events.values()
                    if previous.sequence_scope == event.sequence_scope
                ),
                key=lambda previous: previous.source_sequence or 0,
            )
            if stream:
                previous = stream[-1]
                assert previous.source_sequence is not None and event.source_sequence is not None
                if event.source_sequence != previous.source_sequence + 1:
                    raise _Stop("rejected", "SOURCE_SEQUENCE_NOT_CONTIGUOUS")
                self.sequence_parents[event.event_id] = previous.event_id
        self._enqueue(event)

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

    def _flow(
        self,
        command: AccountingCommand,
        source: str,
        *,
        initial: bool = False,
        reject_stops: bool = True,
    ) -> AccountingTransition:
        flow = command.payload
        assert isinstance(flow, LedgerCashFlow)
        self.mark_session = flow.effective_at.astimezone(ZoneInfo("America/New_York")).date()
        if any(item.flow.cash_flow_id == flow.cash_flow_id for item in self.flows):
            return self._apply(command, source=source, stage=1, reject_stops=reject_stops)
        retained_counts = (len(self.valuations), len(self.wealth), len(self.benchmark_inputs))
        before_valuation_bytes = self.output_bytes
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
        tentative_valuation_bytes = self.output_bytes - before_valuation_bytes
        result = self._apply(command, source=source, stage=1, reject_stops=reject_stops)
        if result.disposition == "rejected":
            # The observed-fact consumer continues with unrelated facts. Failed
            # cash input creates no flow pair or wealth point; preserve only the
            # actual rejection trace and its consumed reduction sequence.
            del self.valuations[retained_counts[0] :]
            del self.wealth[retained_counts[1] :]
            del self.benchmark_inputs[retained_counts[2] :]
            self.output_bytes -= tentative_valuation_bytes
            return result
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
        return result

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
        return _runtime_loss_inputs(
            tuple(self.wealth), self.sequence, self.current.snapshot, self.daily_wealth
        )

    def _evidence(
        self, batch: DailyIntentBatch, phase: Literal["decision", "activation"]
    ) -> DailyRiskEvidence | DailyRuntimeRiskEvidence:
        daily_return, drawdown = self._loss()
        trigger = batch.target.trigger
        if self.continuous:
            if self.runtime_evidence is None:
                raise _Stop("rejected", "RUNTIME_RISK_PRODUCER_REQUIRED")
            return self.runtime_evidence.build(
                snapshot=self.current.snapshot,
                batch=batch,
                phase=phase,
                evaluated_at=self.now,
                accepted_intent_ids=tuple(
                    sorted(self.accepted.get(trigger.execution_session, set()))
                ),
                daily_return=daily_return,
                drawdown=drawdown,
                request_rows=tuple(self.requests.rows),
            )
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
        source_state = self.state
        source_context = self._context(batch.batch_id, before)
        evidence = self._evidence(batch, "decision")
        decision = evaluate_daily_risk(
            self.spec.risk_policy,
            before,
            batch,
            evidence,
            self.now,
        )
        if not decision.approved or not batch.intents:
            self._record_runtime_decision(
                before,
                batch,
                evidence,
                decision,
                (),
                "rejected" if not decision.approved else "no_intents",
                source_state=source_state,
                source_context=source_context,
            )
            self._trace(
                batch.target.trigger.trigger_id,
                "risk_approved" if decision.approved else "risk_rejected",
                batch.target.trigger.source_sha256,
                before,
                reasons=decision.reasons,
                batch=batch,
            )
            return
        prepared = prepare_daily_commitments(
            state=self.state,
            snapshot=before,
            batch=batch,
            decision=decision,
            context=source_context,
            execution_policy=self.spec.execution_policy,
            risk_policy=self.spec.risk_policy,
            accounting=self.accounting,
            attempt_namespace="daily-runtime-attempt" if self.continuous else "model-attempt",
        )
        self.sequence, self._stage_number = prepared.last_reduction_sequence, 6
        if prepared.disposition != "installed":
            # Preserve the historical wrapper's failure boundary for exceptions;
            # only explicit accounting rejection is a batch rollback outcome.
            if any(reason.startswith("INSTALL_EXCEPTION:") for reason in prepared.reasons):
                raise ValueError("invalid commitment accounting transition")
            self._record_runtime_decision(
                before,
                batch,
                evidence,
                decision,
                (),
                "rolled_back",
                source_state=source_state,
                source_context=source_context,
            )
            self._project("atomic-batch-rollback", 6)
            self._trace(
                batch.batch_id,
                "batch_install_rolled_back",
                batch.target.trigger.source_sha256,
                before,
                reasons=prepared.reasons,
                batch=batch,
            )
            return
        self.state, self.current = prepared.state, prepared.transitions[-1]
        self._record_runtime_decision(
            before,
            batch,
            evidence,
            decision,
            prepared.commitments,
            "installed",
            source_state=source_state,
            source_context=source_context,
        )
        for result in prepared.transitions:
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

    def _record_runtime_decision(
        self,
        snapshot: AccountSnapshot,
        batch: DailyIntentBatch,
        evidence: DailyRiskEvidence | DailyRuntimeRiskEvidence,
        decision: DailyRiskDecision,
        commitments: tuple[Commitment, ...],
        disposition: Literal["rejected", "no_intents", "installed", "rolled_back"],
        *,
        source_state: AccountingState,
        source_context: AccountingContext,
    ) -> None:
        if not self.continuous:
            return
        if type(evidence) is not DailyRuntimeRiskEvidence:
            raise _Stop("failed", "CONTINUOUS_EVIDENCE_VERSION_REQUIRED")
        self.runtime_decisions.append(
            ContinuousDecision(
                source_state=source_state,
                source_context=source_context,
                snapshot=snapshot,
                batch=batch,
                evidence=evidence,
                decision=decision,
                installed_commitments=commitments,
                disposition=disposition,
            )
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
            self.sessions[execution].opens_at + timedelta(minutes=5)
            if self.continuous
            else self.sessions[execution].opens_at,
            self.sessions[execution].opens_at + timedelta(minutes=10)
            if self.continuous
            else self.sessions[execution].closes_at,
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

    def _reconcile(self, event: EngineEvent) -> None:
        """Apply planned source facts in this engine, preserving flow/wealth history."""
        batch = event.payload
        assert isinstance(batch, ContinuousReconciliationBatch)
        if not self.continuous or self.baseline_id is None:
            raise _Stop("rejected", "RECONCILIATION_REQUIRES_CONTINUOUS_BASELINE")
        before = self._project(event.event_id, 1)
        plan = plan_reconciliation_facts(
            scope=batch.scope,
            current=self.current,
            facts=batch.facts,
            source_receipts=batch.source_receipts,
            prior_applications=batch.prior_applications,
            context=self._context(event.event_id),
            policy=self.spec.execution_policy,
            source_order=batch.source_order,
        )
        quarantine = set(plan.quarantined_fact_ids)
        unresolved: set[str] = set()
        reasons = set(plan.reasons)
        duplicate: set[str] = set()
        applications: dict[str, FactApplication] = {}
        pending = {item.observation.fact_id for item in plan.candidates} - quarantine
        while pending:
            self._budget()
            ready = reconciliation_ready_facts(plan, pending_fact_ids=tuple(sorted(pending)))
            if not ready:
                unresolved.update(pending)
                reasons.add("CYCLIC_FACT_DEPENDENCY")
                break
            for item in ready:
                identity = item.observation.fact_id
                pending.remove(identity)
                checked = check_reconciliation_candidate(
                    plan,
                    item,
                    current=self.current,
                    blocked_fact_ids=tuple(sorted(quarantine | unresolved)),
                )
                if checked.disposition != "apply":
                    if checked.disposition == "duplicate":
                        assert checked.application is not None
                        applications[identity] = checked.application
                        duplicate.add(identity)
                    else:
                        (quarantine if checked.disposition == "quarantined" else unresolved).add(
                            identity
                        )
                        assert checked.reason is not None
                        reasons.add(checked.reason)
                    continue
                self.processed += 1
                self._budget()
                self.economic = reconciliation_fact_effective_at(item)
                self.mark_session = self.economic.astimezone(ZoneInfo("America/New_York")).date()
                if isinstance(item.command.payload, LedgerCashFlow):
                    result = self._flow(item.command, item.semantic_sha256, reject_stops=False)
                else:
                    result = self._apply(
                        item.command, source=item.semantic_sha256, stage=1, reject_stops=False
                    )
                if result.disposition == "rejected":
                    unresolved.add(identity)
                    reasons.add("CANONICAL_ACCOUNTING_REJECTED_FACT")
                    continue
                if result.due_events:
                    raise _Stop("failed", "OBSERVED_FACT_EMITTED_MODELED_DUE_EVENT")
                assert self._last_apply_context is not None
                application = derive_reconciliation_application(
                    item,
                    current=result,
                    applied_context=self._last_apply_context,
                )
                if application is None:
                    unresolved.add(identity)
                    reasons.add("CANONICAL_ECONOMIC_APPLICATION_UNAVAILABLE")
                else:
                    applications[identity] = application
                reasons.update(result.reasons)
        if reasons:
            self._halt("RECONCILIATION_REQUIRES_OWNER_DISPOSITION")
        self.economic = event.economic_at
        self.mark_session = self.economic.astimezone(ZoneInfo("America/New_York")).date()
        self._project(event.event_id, 1)
        result_batch = AppliedReconciliationBatch(
            self.state,
            self.current,
            tuple(applications[key] for key in sorted(applications)),
            tuple(sorted(duplicate)),
            tuple(sorted(unresolved - quarantine)),
            tuple(sorted(quarantine)),
            tuple(sorted(reasons)),
        )
        self.application_batches.append(result_batch)
        self._trace(
            event.event_id,
            "reconciliation_batch",
            batch.source_closure_sha256,
            before,
            reasons=result_batch.reasons,
        )

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
                and not self.continuous
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
            elif isinstance(payload, ContinuousReconciliationBatch):
                self._reconcile(event)
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
            elif signal.kind == "session_close" and not self.continuous:
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
            if (
                commitment.state == "approved_unsent"
                and not self.state.halted
                and not self.continuous
            ):
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

    def checkpoint(self) -> CausalEngineCheckpoint:
        """Snapshot a closed frontier without restarting strategy/account state."""
        if self._closure_status != "closed":
            raise ValueError("checkpoint requires successful admission and a closed frontier")
        remaining = self._remaining_wall_ns()
        if remaining < 0:
            raise _Stop("cancelled", "WALL_TIME_BUDGET_EXCEEDED")
        result = CausalEngineCheckpoint(
            inputs=self.inputs,
            state=self.state,
            current=self.current,
            strategy_state=self.strategy_state,
            now=self.now,
            economic=self.economic,
            mark_session=self.mark_session,
            frontier=self.frontier,
            sequence=self.sequence,
            stage=self.stage,
            processed=self.processed,
            output_bytes=self.output_bytes,
            retained_knowledge=self.retained_knowledge,
            events=tuple(self.events[key] for key in sorted(self.events)),
            pending_ids=tuple(identity for _, identity in sorted(self.queue)),
            seen=tuple(sorted(self.seen)),
            causal_sources=tuple(sorted(self.causal_sources.items())),
            sequence_parents=tuple(sorted(self.sequence_parents.items())),
            heads=tuple((key, self.heads[key].event_id) for key in sorted(self.heads)),
            benchmarks=tuple(
                (key, self.benchmarks[key].event_id) for key in sorted(self.benchmarks)
            ),
            done_sessions=tuple(sorted(self.done_sessions)),
            valued_sessions=tuple(sorted(self.valued_sessions)),
            accepted=tuple(
                (key, tuple(sorted(self.accepted[key]))) for key in sorted(self.accepted)
            ),
            targets=tuple(sorted(self.targets.items())),
            trace=tuple(self.trace),
            valuations=tuple(self.valuations),
            flows=tuple(self.flows),
            benchmark_inputs=tuple(self.benchmark_inputs),
            wealth=tuple(self.wealth),
            request_rows=tuple(self.requests.rows),
            daily_wealth=self.daily_wealth,
            baseline_id=self.baseline_id,
            terminal_id=self.terminal_id,
            baseline_at=self.baseline_at,
            baseline_economic=self.baseline_economic,
            baseline_session=self.baseline_session,
            remaining_wall_nanoseconds=remaining,
            closed_source_frontiers=tuple(sorted(self.closed_source_frontiers.items())),
            runtime_decisions=tuple(self.runtime_decisions),
        )
        if self.continuous and len(encode_record(result)) > self.spec.max_output_bytes:
            raise _Stop("rejected", "CHECKPOINT_BUDGET_EXCEEDED")
        return result

    @classmethod
    def restore(
        cls,
        checkpoint: CausalEngineCheckpoint,
        *,
        expected_sha256: str,
        accounting: ExecutionAccountingPort,
        strategy: DailyStrategy,
        stop_requested: Callable[[], bool] | None = None,
        runtime_evidence: ContinuousRiskEvidencePort | None = None,
    ) -> _Engine:
        """Restore an exact caller-authenticated checkpoint, without readmission.

        The expected digest comes from the durable account/input chain. A bare
        checkpoint or caller-selected digest is not effect authorization.
        """
        if (
            type(checkpoint) is not CausalEngineCheckpoint
            or checkpoint.semantic_sha256 != expected_sha256
        ):
            raise ValueError("checkpoint differs from retained digest")
        restored = cls(checkpoint.inputs, accounting, strategy, stop_requested, runtime_evidence)
        if not restored.continuous:
            restored._wall_allowance_ns = checkpoint.remaining_wall_nanoseconds
        # The names are a fixed implementation whitelist, never wire-selected.
        for name in (
            "state",
            "current",
            "strategy_state",
            "now",
            "economic",
            "mark_session",
            "frontier",
            "sequence",
            "processed",
            "output_bytes",
            "retained_knowledge",
            "daily_wealth",
            "baseline_id",
            "terminal_id",
            "baseline_at",
            "baseline_economic",
            "baseline_session",
        ):
            setattr(restored, name, getattr(checkpoint, name))
        restored._stage_number = checkpoint.stage
        restored.events = {event.event_id: event for event in checkpoint.events}
        restored.queue = [
            (restored.events[key].knowledge_at, key) for key in checkpoint.pending_ids
        ]
        heapq.heapify(restored.queue)
        restored.seen = set(checkpoint.seen)
        restored.causal_sources = dict(checkpoint.causal_sources)
        restored.sequence_parents = dict(checkpoint.sequence_parents)
        restored.heads = {key: restored.events[value] for key, value in checkpoint.heads}
        restored.benchmarks = {key: restored.events[value] for key, value in checkpoint.benchmarks}
        restored.done_sessions = set(checkpoint.done_sessions)
        restored.valued_sessions = set(checkpoint.valued_sessions)
        restored.accepted = {key: set(value) for key, value in checkpoint.accepted}
        restored.targets = dict(checkpoint.targets)
        restored.trace = list(checkpoint.trace)
        restored.valuations = list(checkpoint.valuations)
        restored.flows = list(checkpoint.flows)
        restored.benchmark_inputs = list(checkpoint.benchmark_inputs)
        restored.wealth = list(checkpoint.wealth)
        restored.requests.rows = list(checkpoint.request_rows)
        restored.closed_source_frontiers = dict(checkpoint.closed_source_frontiers)
        restored.runtime_decisions = list(checkpoint.runtime_decisions)
        restored._closure_status = "closed"
        retained = restored.checkpoint()
        if (
            replace(retained, remaining_wall_nanoseconds=checkpoint.remaining_wall_nanoseconds)
            != checkpoint
        ):
            raise ValueError("restored checkpoint is not exact")
        return restored

    def advance_next_frontier(self) -> bool:
        """Advance the same atomic frontier used by the historical wrapper."""
        if self._closure_status != "closed":
            raise ValueError("advance requires successful admission and a closed frontier")
        if not self.queue or (self.terminal_id is not None and not self.continuous):
            return False
        self._closure_status = "advancing"
        try:
            self._budget()
            instant = self.queue[0][0]
            self.now = instant
            self.frontier += 1
            events: list[EngineEvent] = []
            while self.queue and self.queue[0][0] == instant:
                _, event_id = heapq.heappop(self.queue)
                events.append(self.events[event_id])
            self._frontier(events)
        except BaseException:
            self._closure_status = "failed"
            raise
        self._closure_status = "closed"
        return True

    def run(self) -> EngineResult:
        if self.continuous:
            raise ValueError("continuous input requires explicit closed-frontier admission")
        assert not isinstance(self.spec, ContinuousEngineSpec)
        status: Literal["completed", "cancelled", "failed", "rejected"] = "completed"
        reasons: tuple[str, ...] = ()
        try:
            self._admit()
            while self.advance_next_frontier():
                pass
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


def initialize_continuous_engine(
    inputs: ContinuousEngineInputs,
    *,
    accounting: ExecutionAccountingPort,
    strategy: DailyStrategy,
    runtime_evidence: ContinuousRiskEvidencePort | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> CausalEngineCheckpoint:
    """Prepare one new stream from known inputs through the canonical queue.

    This pure transition needs a durable account transaction before it becomes
    retained state. It performs no source I/O, order dispatch or lease acquisition.
    """
    if type(inputs) is not ContinuousEngineInputs:
        raise ValueError("continuous initialization requires the exact input version")
    engine = _Engine(inputs, accounting, strategy, stop_requested, runtime_evidence)
    engine._admit()
    while engine.queue and engine.queue[0][0] <= inputs.spec.initialized_at:
        engine.advance_next_frontier()
    return engine.checkpoint()


def advance_continuous_engine_with_applications(
    checkpoint: CausalEngineCheckpoint,
    frontier: ClosedEngineFrontier,
    *,
    expected_sha256: str,
    accounting: ExecutionAccountingPort,
    strategy: DailyStrategy,
    runtime_evidence: ContinuousRiskEvidencePort | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> tuple[CausalEngineCheckpoint, tuple[AppliedReconciliationBatch, ...]]:
    """Prepare the next closed source frontier, never consume a future tape.

    Exact input retry is inert. The caller authenticates and atomically retains
    source closure, expected account heads, resulting checkpoint and outbound
    proposals. Each newly admitted continuous step has its own bounded compute
    allowance; finite historical restoration retains its aggregate allowance.
    """
    if (
        type(checkpoint) is not CausalEngineCheckpoint
        or not isinstance(checkpoint.inputs, ContinuousEngineInputs)
        or checkpoint.semantic_sha256 != expected_sha256
        or type(frontier) is not ClosedEngineFrontier
        or frontier.stream_id != checkpoint.inputs.spec.run_id
    ):
        raise ValueError("continuous frontier differs from retained stream/checkpoint")
    previous = dict(checkpoint.closed_source_frontiers).get(frontier.frontier_id)
    if previous is not None:
        if previous != frontier.semantic_sha256:
            raise ValueError("conflicting closed frontier identity")
        return checkpoint, ()
    if (
        frontier.previous_checkpoint_sha256 != expected_sha256
        or frontier.knowledge_at <= checkpoint.now
    ):
        raise ValueError("continuous frontier requires exact predecessor and advancing knowledge")
    engine = _Engine.restore(
        checkpoint,
        expected_sha256=expected_sha256,
        accounting=accounting,
        strategy=strategy,
        runtime_evidence=runtime_evidence,
        stop_requested=stop_requested,
    )
    engine._admit_continuous_events(frontier.events, at=frontier.knowledge_at)
    # A clock-only closure still seals this knowledge boundary through the sole
    # queue. It carries no market, risk or broker freshness assertion.
    signal_id = canonical_id("continuous-closure", frontier.frontier_id)
    engine._enqueue(
        engine._internal(
            signal_id,
            ScheduleSignal("personal-continuous-closure/1", engine.mark_session, "valuation_due"),
            frontier.knowledge_at,
        )
    )
    # Pending calendar rows describe due instants, not evidence that a sleeping
    # worker ran on time. Close overdue timers at this actually admitted boundary
    # while retaining their original economic/due instant. Source receipt times
    # and already-consumed events are never rewritten.
    for _at, identity in engine.queue:
        event = engine.events[identity]
        if isinstance(event.payload, ScheduleSignal) and event.knowledge_at < frontier.knowledge_at:
            engine.events[identity] = replace(event, knowledge_at=frontier.knowledge_at)
    engine.queue = [
        (engine.events[identity].knowledge_at, identity) for _, identity in engine.queue
    ]
    heapq.heapify(engine.queue)
    while engine.queue and engine.queue[0][0] <= frontier.knowledge_at:
        engine.advance_next_frontier()
    engine.closed_source_frontiers[frontier.frontier_id] = frontier.semantic_sha256
    return engine.checkpoint(), tuple(engine.application_batches)


def advance_continuous_engine(
    checkpoint: CausalEngineCheckpoint,
    frontier: ClosedEngineFrontier,
    *,
    expected_sha256: str,
    accounting: ExecutionAccountingPort,
    strategy: DailyStrategy,
    runtime_evidence: ContinuousRiskEvidencePort | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> CausalEngineCheckpoint:
    """Advance the sole engine; application consumers may retain its receipt variant."""
    result, _ = advance_continuous_engine_with_applications(
        checkpoint,
        frontier,
        expected_sha256=expected_sha256,
        accounting=accounting,
        strategy=strategy,
        runtime_evidence=runtime_evidence,
        stop_requested=stop_requested,
    )
    return result


def _runtime_loss_inputs(
    wealth: tuple[WealthPoint, ...],
    sequence: int,
    snapshot: AccountSnapshot,
    daily_wealth: Decimal | None,
) -> tuple[Decimal | None, Decimal | None]:
    if not wealth:
        return None, None
    points = (
        *wealth,
        WealthPoint(
            "risk-" + str(sequence), sequence + 1, snapshot.nav, reasons=snapshot.valuation_reasons
        ),
    )
    value = derive_wealth_path(points)[-1]
    if value.wealth is None or daily_wealth is None:
        return None, value.drawdown
    with localcontext(derived_context()):
        return value.wealth / daily_wealth - 1, value.drawdown


def continuous_runtime_loss_inputs(
    checkpoint: CausalEngineCheckpoint,
) -> tuple[Decimal | None, Decimal | None]:
    """Use the sole engine's loss calculation on its exact retained history."""
    if type(checkpoint.inputs) is not ContinuousEngineInputs:
        raise ValueError("continuous loss inputs require a continuous checkpoint")
    return _runtime_loss_inputs(
        checkpoint.wealth, checkpoint.sequence, checkpoint.current.snapshot, checkpoint.daily_wealth
    )


def continuous_runtime_action_context(
    checkpoint: CausalEngineCheckpoint,
    *,
    command_id: str,
    activation: bool,
    checked_at: datetime | None = None,
) -> AccountingContext:
    """Pure next-reduction context after an already closed actual source frontier.

    This derives values, not source/fence/dispatch authority. The durable composer
    verifies that the exact source closure produced the snapshot and command.
    """
    if type(checkpoint.inputs) is not ContinuousEngineInputs:
        raise ValueError("runtime action context requires a continuous checkpoint")
    spec = checkpoint.inputs.spec
    at = checkpoint.now if checked_at is None else checked_at
    if at < checkpoint.now:
        raise ValueError("runtime context cannot rewind time")
    if activation and checkpoint.current.snapshot.point.knowledge_at > checkpoint.now:
        raise ValueError("runtime action requires the current closed-boundary snapshot")
    return AccountingContext(
        spec.run_id,
        ReductionPoint(checkpoint.frontier, checkpoint.sequence + 1, at, 4),
        checkpoint.economic,
        command_id,
        checkpoint.mark_session,
        spec.instruments,
        checkpoint.current.snapshot if activation else None,
        spec.risk_policy.semantic_sha256 if activation else None,
    )


def apply_continuous_runtime_action(
    checkpoint: CausalEngineCheckpoint,
    action: ContinuousRuntimeAction,
    *,
    expected_sha256: str,
    accounting: ExecutionAccountingPort,
    strategy: DailyStrategy,
    runtime_evidence: ContinuousRiskEvidencePort | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> CausalEngineCheckpoint:
    """Apply one internal canonical command through the same engine and checkpoint.

    Source frontiers cannot carry this action. A current retained source boundary
    must precede it. Metadata records its actual later check time without
    refreshing market snapshots or reading scheduled work. The
    storage composer must authenticate complete attempts, risk and hold sources and
    publish them with this checkpoint. These pure values cannot authorize delivery.
    """
    if (
        type(action) is not ContinuousRuntimeAction
        or type(checkpoint.inputs) is not ContinuousEngineInputs
        or checkpoint.semantic_sha256 != expected_sha256
        or action.stream_id != checkpoint.inputs.spec.run_id
    ):
        raise ValueError("runtime action differs from retained continuous stream")
    previous = dict(checkpoint.closed_source_frontiers).get(action.retained_id)
    if previous is not None:
        if previous != action.semantic_sha256:
            raise ValueError("runtime action identity conflicts with its retained command")
        return checkpoint
    if action.previous_checkpoint_sha256 != expected_sha256 or action.checked_at < checkpoint.now:
        raise ValueError(
            "runtime action requires exact predecessor and original closed-boundary time"
        )
    if action.command is None:
        # Attempt metadata has its own authenticated durable B history. Seal the
        # exact internal event/source identity without inventing a financial
        # command, changing canonical orders or consuming a modeled request.
        # The composer must bind this whole event group to the actual B result.
        engine = _Engine.restore(
            checkpoint,
            expected_sha256=expected_sha256,
            accounting=accounting,
            strategy=strategy,
            runtime_evidence=runtime_evidence,
            stop_requested=stop_requested,
        )
        engine.processed += 1
        engine._budget()
        engine.now = action.checked_at
        engine.closed_source_frontiers[action.retained_id] = action.semantic_sha256
        return engine.checkpoint()
    if action.command.command_id in checkpoint.seen or any(
        command_id == action.command.command_id for command_id, _ in checkpoint.state.commands
    ):
        raise ValueError("runtime action cannot relabel a previously consumed command")
    payload = action.command.payload
    assert isinstance(payload, (ActivateRuntimeCommitments, ReleaseRuntimeUnsent))
    if payload.account_id != checkpoint.state.account_id:
        raise ValueError("runtime action account differs")
    context = continuous_runtime_action_context(
        checkpoint,
        command_id=action.command.command_id,
        activation=isinstance(payload, ActivateRuntimeCommitments),
        checked_at=action.checked_at,
    )
    engine = _Engine.restore(
        checkpoint,
        expected_sha256=expected_sha256,
        accounting=accounting,
        strategy=strategy,
        runtime_evidence=runtime_evidence,
        stop_requested=stop_requested,
    )
    engine.processed += 1
    engine._budget()
    engine.now = action.checked_at
    activation_count = len(payload.terms) if isinstance(payload, ActivateRuntimeCommitments) else 0
    if activation_count and not continuous_request_budget_available(
        checkpoint.request_rows,
        at=action.checked_at,
        count=activation_count,
        low_priority=True,
    ):
        raise ValueError("runtime action exceeds the modeled low-priority request budget")
    result = engine._apply(
        action.command,
        source=action.source_closure_sha256,
        stage=4,
        approved=context.approved_snapshot,
    )
    if (
        result.disposition != "applied"
        or engine._last_apply_context != context
        or result.journal_entries
        or result.due_events
    ):
        raise ValueError("runtime action differs from its exact non-economic canonical context")
    # Commitments/command lineage may change; actual economic and order history may not.
    for name in (
        "submissions",
        "broker_events",
        "event_points",
        "cancel_requests",
        "cash_flows",
        "stock_splits",
        "cash_dividends",
        "dividend_payments",
        "settlement_instructions",
        "settlement_confirmations",
        "marks",
    ):
        if getattr(engine.state, name) != getattr(checkpoint.state, name):
            raise ValueError("runtime action replaced observed financial or order history")
    for _ in range(activation_count):
        engine.requests.record(action.checked_at, low_priority=True)
    engine.closed_source_frontiers[action.retained_id] = action.semantic_sha256
    return engine.checkpoint()
