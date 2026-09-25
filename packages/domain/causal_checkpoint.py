"""Exact, typed continuation state for the sole causal scheduler.

This first schema represents an admitted finite input manifest. It is not a
forward-source qualification or an execution authority. Durable callers must
bind its digest to the retained input and account journal before restoration.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import ClassVar

from packages.domain.accounting_contracts import AccountingState, AccountingTransition
from packages.domain.continuous_engine_contracts import ContinuousDecision, ContinuousEngineInputs
from packages.domain.engine_contracts import (
    DailyStrategyState,
    DailyTarget,
    EngineEvent,
    EngineInputs,
    EngineTraceRow,
)
from packages.domain.personal_contracts import ContractRecord
from packages.domain.report_contracts import BenchmarkValuationInput, ExternalFlowRow, ValuationRow
from packages.domain.wealth import WealthPoint


@dataclass(frozen=True, slots=True)
class CausalEngineCheckpoint(ContractRecord):
    contract_version: ClassVar[str] = "personal-causal-checkpoint/1"

    inputs: EngineInputs | ContinuousEngineInputs
    state: AccountingState
    current: AccountingTransition
    strategy_state: DailyStrategyState
    now: datetime
    economic: datetime
    mark_session: date
    frontier: int
    sequence: int
    stage: int
    processed: int
    output_bytes: int
    retained_knowledge: datetime
    events: tuple[EngineEvent, ...]
    pending_ids: tuple[str, ...]
    seen: tuple[str, ...]
    causal_sources: tuple[tuple[str, str], ...]
    sequence_parents: tuple[tuple[str, str], ...]
    heads: tuple[tuple[tuple[date, str], str], ...]
    benchmarks: tuple[tuple[datetime, str], ...]
    done_sessions: tuple[date, ...]
    valued_sessions: tuple[date, ...]
    accepted: tuple[tuple[date, tuple[str, ...]], ...]
    targets: tuple[tuple[str, DailyTarget], ...]
    trace: tuple[EngineTraceRow, ...]
    valuations: tuple[ValuationRow, ...]
    flows: tuple[ExternalFlowRow, ...]
    benchmark_inputs: tuple[BenchmarkValuationInput, ...]
    wealth: tuple[WealthPoint, ...]
    request_rows: tuple[tuple[datetime, bool], ...]
    daily_wealth: Decimal | None
    baseline_id: str | None
    terminal_id: str | None
    baseline_at: datetime
    baseline_economic: datetime
    baseline_session: date
    remaining_wall_nanoseconds: int
    closed_source_frontiers: tuple[tuple[str, str], ...] = ()
    runtime_decisions: tuple[ContinuousDecision, ...] = ()

    def __post_init__(self) -> None:
        super(CausalEngineCheckpoint, self).__post_init__()
        if self.state.account_id != self.inputs.spec.account_id or self.current.state != self.state:
            raise ValueError("checkpoint account projection and state differ")
        if min(self.frontier, self.sequence, self.processed, self.output_bytes) < 0:
            raise ValueError("checkpoint counters must be nonnegative")
        if not 0 <= self.remaining_wall_nanoseconds <= self.inputs.spec.max_wall_seconds * 10**9:
            raise ValueError("checkpoint remaining wall budget is invalid")
        if not 0 <= self.stage <= 8 or self.economic > self.now:
            raise ValueError("checkpoint stage/time is invalid")
        if (
            self.sequence < self.state.revision
            or self.current.snapshot.point.knowledge_at > self.now
        ):
            raise ValueError("checkpoint projection precedes its required state")
        if len(self.events) > self.inputs.spec.max_events:
            raise ValueError("checkpoint exceeds event bound")
        ids = tuple(event.event_id for event in self.events)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("checkpoint event identities must be sorted unique")
        events = {event.event_id: event for event in self.events}
        if len(self.pending_ids) != len(set(self.pending_ids)) or any(
            identity not in events for identity in self.pending_ids
        ):
            raise ValueError("checkpoint pending event binding differs")
        if any(events[identity].knowledge_at <= self.now for identity in self.pending_ids):
            raise ValueError("checkpoint cannot retain an unclosed earlier frontier")
        if self.seen != tuple(sorted(set(self.seen))):
            raise ValueError("checkpoint consumed identities must be sorted unique")
        for values in (self.done_sessions, self.valued_sessions):
            if values != tuple(sorted(set(values))):
                raise ValueError("checkpoint sets must be sorted unique")
        if set(self.pending_ids) & set(self.seen):
            raise ValueError("checkpoint pending event was already consumed")
        if set(ids) - set(self.pending_ids) - set(self.seen):
            raise ValueError("checkpoint has an event outside consumed or pending state")
        if not set(self.valued_sessions) <= set(self.done_sessions):
            raise ValueError("checkpoint valuation session was not closed")
        for mapping in (
            self.causal_sources,
            self.sequence_parents,
            self.heads,
            self.benchmarks,
            self.accepted,
            self.targets,
            self.closed_source_frontiers,
        ):
            keys = tuple(key for key, _ in mapping)
            if keys != tuple(sorted(set(keys))):
                raise ValueError("checkpoint map keys must be sorted unique")
        if any(identity not in events for _, identity in (*self.heads, *self.benchmarks)):
            raise ValueError("checkpoint market head has no retained event")
        if any(at > self.now for at, _ in self.request_rows):
            raise ValueError("checkpoint request history contains future work")
