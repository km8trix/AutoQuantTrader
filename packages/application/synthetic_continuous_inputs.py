"""Pure synthetic daily inputs for the existing stateful-simulation engine.

This converts the established engineering fixture, not market data. It creates
no controls, runtime evidence, orders, fills, persistence or execution authority.
Callers supply build pins; this module never discovers provenance from disk.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Literal

from packages.application.personal_inputs import synthetic_engine_inputs
from packages.domain.continuous_engine_contracts import ContinuousEngineInputs, ContinuousEngineSpec
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import DailyPrice, EngineEvent, EngineInputs
from packages.domain.personal_contracts import VersionPin, content_digest


@dataclass(frozen=True, slots=True)
class SyntheticContinuousInputs:
    inputs: ContinuousEngineInputs
    daily_events: tuple[EngineEvent, ...]


def synthetic_continuous_inputs(
    *,
    fixture: Literal["flat", "regime"],
    pins: tuple[VersionPin, ...],
    session_count: int = 8,
    warmup_count: int = 2,
) -> SyntheticContinuousInputs:
    """Reuse the product fixture and its risk/cost defaults without open-fill proxies."""
    finite = synthetic_engine_inputs(
        fixture=fixture,
        pins=pins,
        session_count=session_count,
        warmup_count=warmup_count,
        configuration=ReferenceConfiguration(lookback=2),
    )
    first = next(
        session
        for session in finite.spec.calendar.sessions
        if session.session_label == finite.spec.evaluation.scored_sessions[0]
    )
    return _continuous_from_finite(finite, initialized_at=first.opens_at - timedelta(minutes=30))


def _continuous_from_finite(
    finite: EngineInputs, *, initialized_at: datetime
) -> SyntheticContinuousInputs:
    """Share the existing daily-only conversion; the caller chooses its time model."""
    warmup = tuple(
        sorted(
            (
                event
                for event in finite.events
                if isinstance(event.payload, DailyPrice)
                and event.payload.session in finite.spec.evaluation.warmup_sessions
            ),
            key=lambda event: event.event_id,
        )
    )
    deployment = "synthetic-stream"
    binding = content_digest(
        (
            "synthetic-continuous-account-binding/1",
            finite.spec.account_id,
            deployment,
            finite.spec.instruments,
        )
    )
    spec = ContinuousEngineSpec(
        account_id=finite.spec.account_id,
        deployment_id=deployment,
        account_binding_sha256=binding,
        calendar=finite.spec.calendar,
        instruments=finite.spec.instruments,
        strategy=finite.spec.strategy,
        strategy_configuration=finite.spec.strategy_configuration,
        window=finite.spec.evaluation,
        execution_policy=replace(
            finite.spec.execution_policy,
            model_id="observed-facts-v1",
            settlement_model="observed-only-v1",
            correction_settlement="explicit-only-v1",
            terminal_model="observed-only-v1",
        ),
        risk_policy=replace(
            finite.spec.risk_policy, policy_id="personal-daily-stateful-simulation/1"
        ),
        pins=finite.spec.pins,
        initial_state_sha256=finite.initial_state.semantic_sha256,
        bootstrap_events_sha256=content_digest(warmup),
        initialized_at=initialized_at,
        initial_cash=finite.spec.initial_cash,
        environment="stateful_simulation",
        source_mode="synthetic_observed",
        live_authorized=False,
    )
    inputs = ContinuousEngineInputs(
        spec=spec, initial_state=finite.initial_state, bootstrap_events=warmup
    )
    daily_events = tuple(
        sorted(
            (
                event
                for event in finite.events
                if isinstance(event.payload, DailyPrice)
                and event.payload.session in spec.window.scored_sessions
            ),
            key=lambda event: (event.knowledge_at, event.event_id),
        )
    )
    return SyntheticContinuousInputs(inputs, daily_events)
