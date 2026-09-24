"""Actual engine flow bookkeeping around an explicitly rejected observed fact."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from packages.application.causal_engine import _Engine, _Stop
from packages.application.reference_strategy import ReferenceStrategy
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.accounting_contracts import AccountingCommand
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from tests.unit.test_continuous_engine import FixtureEvidence, inputs_and_prices, start


class RejectSelectedFlow:
    def __init__(self, rejected):
        self.actual = PersonalAccounting()
        self.rejected = rejected

    def project(self, **kwargs):
        return self.actual.project(**kwargs)

    def advance(self, *, state, command, context, policy):
        if command.command_id == self.rejected:
            return replace(
                self.actual.project(state=state, context=context, policy=policy),
                disposition="rejected",
                reasons=("INJECTED_FACT_REJECTION",),
            )
        return self.actual.advance(state=state, command=command, context=context, policy=policy)


def case():
    inputs, _ = inputs_and_prices()
    checkpoint = start(inputs)
    at = checkpoint.now + timedelta(seconds=1)
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(100),
        effective_at=at,
        recorded_at=at,
        external_reference="rejected-source-flow",
    )
    accounting = RejectSelectedFlow(flow.cash_flow_id)
    engine = _Engine.restore(
        checkpoint,
        expected_sha256=checkpoint.semantic_sha256,
        accounting=accounting,
        strategy=ReferenceStrategy(),
        runtime_evidence=FixtureEvidence(inputs.spec),
    )
    engine.now = engine.economic = at
    engine.frontier += 1
    return engine, flow


def test_rejected_observed_flow_preserves_only_rejection_without_partial_wealth_pair():
    engine, flow = case()
    before = (
        engine.state,
        tuple(engine.flows),
        tuple(engine.valuations),
        tuple(engine.wealth),
        tuple(engine.benchmark_inputs),
    )
    result = engine._flow(AccountingCommand(flow.cash_flow_id, flow), "a" * 64, reject_stops=False)
    assert result.disposition == "rejected"
    assert before == (
        engine.state,
        tuple(engine.flows),
        tuple(engine.valuations),
        tuple(engine.wealth),
        tuple(engine.benchmark_inputs),
    )
    assert engine.trace[-1].kind == "accounting_rejected"
    assert engine.trace[-1].event_id == flow.cash_flow_id
    assert flow.cash_flow_id not in engine.seen
    # An unrelated real cash fact still posts through the same engine instance.
    valid = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(200),
        effective_at=engine.now,
        recorded_at=engine.now,
        external_reference="independent-valid-flow",
    )
    applied = engine._flow(
        AccountingCommand(valid.cash_flow_id, valid), "b" * 64, reject_stops=False
    )
    assert applied.disposition == "applied"
    assert applied.snapshot.point.stage == 1
    assert engine.current.snapshot.point.stage == 8
    assert engine.flows[-1].flow == valid
    assert len(engine.valuations) == len(before[2]) + 2
    assert engine.current.snapshot.trade_date_cash == Decimal(10200)


def test_default_reducer_rejection_still_stops_historical_consumer():
    engine, flow = case()
    with pytest.raises(_Stop, match="ACCOUNTING_COMMAND_REJECTED"):
        engine._flow(AccountingCommand(flow.cash_flow_id, flow), "a" * 64)
