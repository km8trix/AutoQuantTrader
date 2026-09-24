"""Pure forward continuation; synthetic producers confer no durable authority."""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.application.causal_engine import (
    _Stop,
    advance_continuous_engine,
    initialize_continuous_engine,
)
from packages.application.personal_codec import decode_record, encode_record
from packages.application.personal_inputs import synthetic_engine_inputs
from packages.application.reference_strategy import ReferenceStrategy
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import (
    ClosedEngineFrontier,
    ContinuousEngineInputs,
    ContinuousEngineSpec,
)
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.daily_runtime_contracts import RuntimeCommitmentBinding
from packages.domain.daily_runtime_risk import (
    build_daily_runtime_evidence,
    runtime_source_value_sha256,
)
from packages.domain.engine_contracts import BenchmarkPrice, DailyPrice
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads
from tests.unit.test_causal_checkpoint import PINS
from tests.unit.test_daily_risk_snapshot import inventory, runtime_case


def inputs_and_prices(fixture="flat", kind="buy_hold"):
    finite = synthetic_engine_inputs(
        fixture=fixture,
        pins=PINS,
        session_count=8,
        warmup_count=2,
        configuration=ReferenceConfiguration(kind=kind, lookback=2),
    )
    first = next(
        s
        for s in finite.spec.calendar.sessions
        if s.session_label == finite.spec.evaluation.scored_sessions[0]
    )
    initialized = first.opens_at - timedelta(minutes=30)
    prices = tuple(event for event in finite.events if isinstance(event.payload, DailyPrice))
    warmup = tuple(
        sorted(
            (
                event
                for event in prices
                if event.payload.session in finite.spec.evaluation.warmup_sessions
            ),
            key=lambda event: event.event_id,
        )
    )
    spec = ContinuousEngineSpec(
        account_id=finite.spec.account_id,
        deployment_id="synthetic-stream",
        account_binding_sha256="a" * 64,
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
        pins=PINS,
        initial_state_sha256=finite.initial_state.semantic_sha256,
        bootstrap_events_sha256=content_digest(warmup),
        initialized_at=initialized,
    )
    return ContinuousEngineInputs(
        spec=spec, initial_state=finite.initial_state, bootstrap_events=warmup
    ), tuple(
        sorted(
            (e for e in prices if e.payload.session in spec.window.scored_sessions),
            key=lambda event: (event.knowledge_at, event.event_id),
        )
    )


class FixtureEvidence:
    """Explicit unit fixture. SQL/source authentication is tested elsewhere."""

    def __init__(self, spec, *, stale_cash=False):
        self.spec, self.stale_cash = spec, stale_cash

    def build(
        self,
        *,
        snapshot,
        batch,
        phase,
        evaluated_at,
        accepted_intent_ids,
        daily_return,
        drawdown,
        request_rows,
    ):
        assignment, _, _, refs, producers, _ = runtime_case(
            snapshot=snapshot, batch=batch, phase=phase, now=evaluated_at
        )
        producers = replace(
            producers,
            producers=tuple(
                replace(p, account_scope=snapshot.account_id) for p in producers.producers
            ),
        )
        assignment = replace(
            assignment,
            account_id=snapshot.account_id,
            account_binding_sha256=self.spec.account_binding_sha256,
            policy=self.spec.risk_policy,
            strategy=self.spec.strategy,
            configuration_sha256=content_digest(self.spec.strategy_configuration),
            instrument_symbols=self.spec.instruments,
            producer_map_sha256=producers.semantic_sha256,
            effective_at=self.spec.initialized_at,
        )
        obligations = inventory(
            tuple(
                RuntimeCommitmentBinding(
                    account_id=snapshot.account_id,
                    commitment=c,
                    origin="daily_runtime",
                    source_id=c.commitment_id,
                    source_sha256=c.semantic_sha256,
                    original_policy_sha256=c.policy_sha256,
                    projection=VersionPin("fixture", "unit-only/1", "b" * 64),
                )
                for c in snapshot.commitments
            )
        )
        heads = ReconciliationHeads(
            snapshot.journal_sha256,
            snapshot.order_sha256,
            obligations.semantic_sha256,
            0,
            "b" * 64,
            0,
            1,
        )
        reconciliation = replace(
            refs.reconciliation,
            scope=replace(
                refs.reconciliation.scope,
                account_id=snapshot.account_id,
                binding_sha256=assignment.account_binding_sha256,
            ),
            heads=heads,
        )
        refs = replace(
            refs,
            assignment_sha256=assignment.semantic_sha256,
            heads=heads,
            source_session=batch.target.trigger.source_session,
            execution_session=batch.target.trigger.execution_session,
            obligations=obligations,
            reconciliation=reconciliation,
            sources=(),
            accepted_intent_ids=accepted_intent_ids,
            daily_return=daily_return,
            drawdown=drawdown,
        )
        original_sources = runtime_case(
            snapshot=snapshot, batch=batch, phase=phase, now=evaluated_at
        )[3].sources
        refs = replace(
            refs,
            sources=tuple(
                replace(
                    source,
                    spec=next(p for p in producers.producers if p.role == source.spec.role),
                    account_id=snapshot.account_id,
                    account_binding_sha256=assignment.account_binding_sha256,
                    value_sha256=runtime_source_value_sha256(
                        source.spec.role, snapshot, batch, refs
                    ),
                    valid_until=evaluated_at
                    if self.stale_cash and source.spec.role == "cash"
                    else source.valid_until,
                )
                for source in original_sources
            ),
        )
        return build_daily_runtime_evidence(
            assignment, snapshot, batch, refs, producer_map=producers, evaluated_at=evaluated_at
        )


def start(inputs):
    return initialize_continuous_engine(
        inputs, accounting=PersonalAccounting(), strategy=ReferenceStrategy()
    )


def step(checkpoint, events, *, at=None, identity=None, evidence=None):
    at = at or max(e.knowledge_at for e in events)
    frontier = ClosedEngineFrontier(
        frontier_id=identity or "closure-" + at.isoformat(),
        stream_id=checkpoint.inputs.spec.run_id,
        previous_checkpoint_sha256=checkpoint.semantic_sha256,
        source_frontier_sha256=content_digest(events),
        knowledge_at=at,
        events=tuple(sorted(events, key=lambda e: e.event_id)),
    )
    return advance_continuous_engine(
        checkpoint,
        frontier,
        expected_sha256=checkpoint.semantic_sha256,
        accounting=PersonalAccounting(),
        strategy=ReferenceStrategy(),
        runtime_evidence=evidence or FixtureEvidence(checkpoint.inputs.spec),
    ), frontier


def economic_values(checkpoint):
    return (
        checkpoint.state,
        checkpoint.strategy_state,
        checkpoint.trace,
        checkpoint.runtime_decisions,
        checkpoint.done_sessions,
        checkpoint.accepted,
        checkpoint.valuations,
        checkpoint.request_rows,
    )


@pytest.mark.parametrize("fixture,kind", [("flat", "buy_hold"), ("regime", "trend_sma")])
def test_incremental_inputs_and_restart_produce_identical_decisions_without_simulated_orders(
    fixture, kind
):
    inputs, prices = inputs_and_prices(fixture, kind)
    initial = start(inputs)
    assert initial.state.cash_flows and initial.runtime_decisions == ()
    assert not any(e.event_id in {p.event_id for p in prices} for e in initial.events)
    continuous, restarted = initial, initial
    for at in sorted({event.knowledge_at for event in prices}):
        group = tuple(event for event in prices if event.knowledge_at == at)
        continuous, _ = step(continuous, group)
        restarted, _ = step(restarted, group)
        restarted = decode_record(encode_record(restarted), CausalEngineCheckpoint)
        assert economic_values(restarted) == economic_values(continuous)
    assert any(d.disposition == "installed" for d in continuous.runtime_decisions)
    assert continuous.state.broker_events == ()
    assert continuous.state.settlement_instructions == ()
    assert continuous.request_rows == ()
    assert all(c.state == "approved_unsent" for c in continuous.state.commitments)
    assert not any("activation_risk" in row.kind for row in continuous.trace)
    # No future knowledge was admitted merely because it appeared in a calendar.
    assert (
        max(e.knowledge_at for e in continuous.events if isinstance(e.payload, DailyPrice))
        == prices[-1].knowledge_at
    )
    assert len(continuous.state.cash_flows) == 1


def test_expiry_keeps_unresolved_hold_and_duplicate_closure_is_inert():
    inputs, prices = inputs_and_prices()
    checkpoint, frontier = step(start(inputs), (prices[0],))
    accepted = checkpoint.state.commitments[0]
    assert accepted.expires_at - accepted.not_before == timedelta(minutes=5)
    later, _ = step(checkpoint, (), at=accepted.expires_at + timedelta(hours=8))
    assert later.state.commitments == checkpoint.state.commitments
    repeated = advance_continuous_engine(
        later,
        frontier,
        expected_sha256=later.semantic_sha256,
        accounting=PersonalAccounting(),
        strategy=ReferenceStrategy(),
    )
    assert repeated is later
    with pytest.raises(ValueError, match="conflicting closed frontier"):
        advance_continuous_engine(
            later,
            replace(frontier, source_frontier_sha256="c" * 64),
            expected_sha256=later.semantic_sha256,
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(),
        )


def test_stale_mandatory_source_rejects_new_commitment_and_observation_continues():
    inputs, prices = inputs_and_prices()
    checkpoint, _ = step(
        start(inputs), (prices[0],), evidence=FixtureEvidence(inputs.spec, stale_cash=True)
    )
    assert checkpoint.runtime_decisions[0].disposition == "rejected"
    assert "RUNTIME_SOURCE_EXPIRED:cash" in checkpoint.runtime_decisions[0].decision.reasons
    assert checkpoint.state.commitments == ()
    later, _ = step(checkpoint, (prices[1],))
    assert prices[1].event_id in later.seen
    assert len(later.state.cash_flows) == 1


def test_late_price_does_not_reopen_cutoff_or_retroactively_dispatch():
    inputs, prices = inputs_and_prices()
    following = next(
        s for s in inputs.spec.calendar.sessions if s.session_label > prices[0].payload.session
    )
    cutoff = following.opens_at - timedelta(minutes=30)
    checkpoint, _ = step(start(inputs), (), at=cutoff)
    assert checkpoint.state.halted
    late = replace(prices[0], knowledge_at=cutoff + timedelta(minutes=1))
    later, _ = step(checkpoint, (late,))
    assert late.event_id in later.seen
    assert later.runtime_decisions == () and later.state.commitments == ()


def test_frontier_missing_producer_or_wrong_predecessor_cannot_publish_partial_result():
    inputs, prices = inputs_and_prices()
    checkpoint = start(inputs)
    frontier = ClosedEngineFrontier(
        frontier_id="first",
        stream_id=inputs.spec.run_id,
        previous_checkpoint_sha256=checkpoint.semantic_sha256,
        source_frontier_sha256=content_digest(prices[0]),
        knowledge_at=prices[0].knowledge_at,
        events=(prices[0],),
    )
    for bad in (
        replace(frontier, previous_checkpoint_sha256="b" * 64),
        replace(frontier, knowledge_at=checkpoint.now, events=()),
    ):
        with pytest.raises(ValueError, match="predecessor"):
            advance_continuous_engine(
                checkpoint,
                bad,
                expected_sha256=checkpoint.semantic_sha256,
                accounting=PersonalAccounting(),
                strategy=ReferenceStrategy(),
            )
    with pytest.raises(_Stop) as missing:
        advance_continuous_engine(
            checkpoint,
            frontier,
            expected_sha256=checkpoint.semantic_sha256,
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(),
        )
    assert missing.value.reason == "RUNTIME_RISK_PRODUCER_REQUIRED"
    assert checkpoint.state.commitments == () and checkpoint.runtime_decisions == ()


def test_sleeping_past_cutoff_does_not_backdate_a_due_decision():
    inputs, prices = inputs_and_prices()
    # A daily row is known after the close but before the declared 20:00 callback.
    early = replace(
        prices[0],
        knowledge_at=prices[0].economic_at + timedelta(minutes=30),
        provenance=replace(
            prices[0].provenance,
            simulated_available_at=prices[0].economic_at + timedelta(minutes=30),
            assumption_id="explicit-early-delivery-fixture/1",
        ),
    )
    checkpoint, _ = step(start(inputs), (early,))
    assert checkpoint.runtime_decisions == ()
    following = next(
        s for s in inputs.spec.calendar.sessions if s.session_label > early.payload.session
    )
    resumed_at = following.opens_at + timedelta(minutes=30)
    resumed, _ = step(checkpoint, (), at=resumed_at)
    assert resumed.state.halted
    assert resumed.runtime_decisions == () and resumed.state.commitments == ()
    due = next(
        e
        for e in resumed.events
        if getattr(e.payload, "kind", None) == "decision_due"
        and e.payload.source_session == early.payload.session
    )
    assert due.knowledge_at == resumed_at
    assert due.economic_at == prices[0].knowledge_at


def test_recorded_mode_requires_raw_receipt_binding_and_preserves_observed_times():
    inputs, prices = inputs_and_prices()

    def recorded(event):
        return replace(
            event,
            provenance=replace(
                event.provenance,
                data_class="recorded_as_observed",
                observed_at=event.provenance.simulated_available_at,
                raw_sha256="d" * 64,
                simulated_available_at=None,
                assumption_id=None,
            ),
        )

    bootstrap = tuple(recorded(event) for event in inputs.bootstrap_events)
    spec = replace(
        inputs.spec,
        source_mode="recorded_as_observed",
        bootstrap_events_sha256=content_digest(bootstrap),
    )
    declared = replace(inputs, spec=spec, bootstrap_events=bootstrap)
    checkpoint = start(declared)
    event = recorded(prices[0])
    missing_raw = replace(event, provenance=replace(event.provenance, raw_sha256=None))
    with pytest.raises(_Stop) as rejected:
        step(checkpoint, (missing_raw,))
    assert rejected.value.reason == "OBSERVED_SOURCE_REQUIRES_RETAINED_CAPTURE"
    advanced, _ = step(checkpoint, (event,))
    retained = next(e for e in advanced.events if e.event_id == event.event_id)
    assert retained.provenance == event.provenance
    assert retained.knowledge_at == event.knowledge_at
    assert decode_record(encode_record(advanced), CausalEngineCheckpoint) == advanced
    # Unit-constructed source metadata exercises shape only; this is no actual
    # authorized provider capture or durable source-authentication evidence.


def test_continuous_checkpoint_enforces_its_actual_serialized_byte_limit():
    inputs, _ = inputs_and_prices()
    with pytest.raises(_Stop) as rejected:
        start(replace(inputs, spec=replace(inputs.spec, max_output_bytes=100)))
    assert rejected.value.reason in {"OUTPUT_BUDGET_EXCEEDED", "CHECKPOINT_BUDGET_EXCEEDED"}


def test_bootstrap_preserves_earlier_knowledge_and_checks_original_availability():
    inputs, _ = inputs_and_prices()
    assert all(event.knowledge_at < inputs.spec.initialized_at for event in inputs.bootstrap_events)
    checkpoint = start(inputs)
    retained = {event.event_id: event for event in checkpoint.events}
    assert all(retained[event.event_id] == event for event in inputs.bootstrap_events)
    original = inputs.bootstrap_events[0]
    bad = replace(
        original,
        provenance=replace(
            original.provenance, simulated_available_at=original.knowledge_at + timedelta(seconds=1)
        ),
    )
    events = (bad, *inputs.bootstrap_events[1:])
    with pytest.raises(_Stop) as failure:
        start(
            replace(
                inputs,
                bootstrap_events=events,
                spec=replace(inputs.spec, bootstrap_events_sha256=content_digest(events)),
            )
        )
    assert failure.value.reason == "EVENT_PRECEDES_DECLARED_AVAILABILITY"


def test_implicit_source_sequence_predecessor_participates_in_cross_source_dag():
    inputs, prices = inputs_and_prices()
    original = prices[0]
    benchmark = BenchmarkPrice(
        "unit-benchmark", original.payload.close_price, "synthetic_total_return_units"
    )
    proto = replace(
        original,
        payload=benchmark,
        provenance=replace(original.provenance, normalized_sha256=content_digest(benchmark)),
    )
    z = replace(proto, event_id="z1", sequence_scope="z", source_sequence=1)
    a1 = replace(
        proto, event_id="a1", sequence_scope="a", source_sequence=1, predecessor_ids=("z1",)
    )
    a2 = replace(proto, event_id="a2", sequence_scope="a", source_sequence=2)
    checkpoint, _ = step(start(inputs), (a2, z, a1))
    assert {"z1", "a1", "a2"} <= set(checkpoint.seen)
    assert dict(checkpoint.sequence_parents)["a2"] == "a1"
    reversed_input, _ = step(start(inputs), (a1, z, a2))
    assert economic_values(checkpoint) == economic_values(reversed_input)


def test_decision_retains_exact_canonical_install_source_for_durable_preparation():
    from packages.application.daily_commitment_install import prepare_daily_commitments

    inputs, prices = inputs_and_prices()
    checkpoint = start(inputs)
    earliest = min(event.knowledge_at for event in prices)
    checkpoint, _ = step(
        checkpoint, tuple(event for event in prices if event.knowledge_at == earliest)
    )
    decision = next(
        value for value in checkpoint.runtime_decisions if value.disposition == "installed"
    )
    prepared = prepare_daily_commitments(
        state=decision.source_state,
        snapshot=decision.snapshot,
        batch=decision.batch,
        decision=decision.decision,
        context=decision.source_context,
        execution_policy=inputs.spec.execution_policy,
        risk_policy=inputs.spec.risk_policy,
        accounting=PersonalAccounting(),
        attempt_namespace="daily-runtime-attempt",
    )
    assert prepared.commitments == decision.installed_commitments
    assert decision.source_state.semantic_sha256 == decision.snapshot.state_sha256
    assert (
        decision.source_context.point.reduction_sequence
        == decision.snapshot.point.reduction_sequence + 1
    )
    with pytest.raises(ValueError, match="canonical preparation source"):
        replace(
            decision,
            source_state=replace(decision.source_state, halted=not decision.source_state.halted),
        )
    with pytest.raises(ValueError, match="canonical preparation source"):
        replace(
            decision, source_context=replace(decision.source_context, point=decision.snapshot.point)
        )
