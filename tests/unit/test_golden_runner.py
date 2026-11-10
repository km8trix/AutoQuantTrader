from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import timedelta
from decimal import Decimal

import pytest

from packages.backtest.golden_runner import run_golden_backtest
from packages.domain.backtest_report import BacktestRunStatus
from packages.domain.batch_risk import BatchRiskDecisionStatus
from packages.domain.ledger_reducer import LedgerEntryKind
from packages.domain.models import Side
from packages.domain.settlement_ledger import SettlementStatus


def test_golden_runner_composes_raw_causal_execution_and_terminal_proofs() -> None:
    run = run_golden_backtest()

    assert run.result.status is BacktestRunStatus.COMPLETED
    assert run.result == run.manifest.result
    assert run.result.report_sha256 == run.report.report_sha256
    assert run.result.report_artifact_sha256 == run.report.artifact_sha256
    assert run.manifest.run_id == run.manifest.manifest_sha256
    assert run.manifest.accounting_evidence_sha256 == run.report.accounting_evidence_sha256
    assert run.manifest.strategy.strategy_replay_sha256 == (run.trace.strategy_semantic_sha256)

    assert tuple(batch.events[0].close_price for batch in run.trace.replay.batches) == (
        Decimal("100"),
        Decimal("101"),
        Decimal("53"),
        Decimal("55"),
    )
    assert tuple(event.close_price for event in run.trace.market_events[-2:]) == (
        Decimal("54.50"),
        Decimal("55"),
    )
    assert {event.source for event in run.trace.market_events} == {"golden-raw-fixture-v1"}
    assert tuple(target.targets[0].quantity for target in run.trace.targets) == (
        Decimal("4"),
        Decimal("0"),
    )
    assert tuple((intent.side, intent.quantity) for intent in run.trace.intents) == (
        (Side.BUY, Decimal("4")),
        (Side.SELL, Decimal("8")),
    )
    assert all(
        decision.status is BatchRiskDecisionStatus.APPROVED for decision in run.trace.risk_decisions
    )

    buy, sell = run.trace.broker_results
    assert buy.fill_evidence is not None
    assert sell.fill_evidence is not None
    assert buy.fill_evidence.occurred_at > buy.activation_at
    assert sell.fill_evidence.occurred_at > sell.activation_at
    assert (
        buy.fill_evidence.terms.reference_price,
        buy.fill_evidence.terms.execution_price,
        buy.fill_evidence.terms.total_fee,
    ) == (Decimal("101"), Decimal("101.07"), Decimal("0.54"))
    assert (
        sell.fill_evidence.terms.reference_price,
        sell.fill_evidence.terms.execution_price,
        sell.fill_evidence.terms.total_fee,
    ) == (Decimal("55"), Decimal("54.93"), Decimal("0.58"))
    assert buy.fill_evidence.source_event_sha256 == (
        run.trace.replay.batches[1].events[0].semantic_sha256
    )
    assert sell.fill_evidence.source_event_sha256 == (
        run.trace.replay.batches[3].events[0].semantic_sha256
    )


def test_golden_economics_reconcile_account_actions_report_and_settlement() -> None:
    run = run_golden_backtest()
    buy, action, final = run.report.positions

    assert (
        buy.quantity,
        buy.cost_basis,
        buy.mark_price,
        buy.market_value,
        buy.realized_pnl,
        buy.unrealized_pnl,
    ) == (
        Decimal("4"),
        Decimal("404.28"),
        Decimal("101"),
        Decimal("404"),
        Decimal("-0.54"),
        Decimal("-0.28"),
    )
    assert (
        action.quantity,
        action.cost_basis,
        action.mark_price,
        action.market_value,
        action.dividend_income,
    ) == (
        Decimal("8"),
        Decimal("404.28"),
        Decimal("53"),
        Decimal("424"),
        Decimal("10"),
    )
    assert (
        final.quantity,
        final.cost_basis,
        final.mark_price,
        final.market_value,
        final.realized_pnl,
        final.execution_costs,
    ) == (
        Decimal("0"),
        Decimal("0"),
        Decimal("55"),
        Decimal("0"),
        Decimal("44.04"),
        Decimal("1.12"),
    )

    assert run.trace.stock_split.post_split_quantity == Decimal("8")
    assert run.trace.cash_dividend.amount == Decimal("10")
    assert run.trace.final_account.cash == Decimal("1044.04")
    assert run.trace.final_account.equity == Decimal("1044.04")
    assert run.report.metrics.ending_equity == Decimal("1044.04")
    assert run.report.metrics.total_return == Decimal("0.04404")
    assert run.report.metrics.realized_pnl == Decimal("44.04")
    assert run.report.trades[0].gross_pnl == Decimal("35.16")
    assert run.report.trades[0].net_pnl == Decimal("34.04")

    initial, after_buy, final_settlement = run.trace.settlement_projections
    assert initial.available_cash == Decimal("1000")
    assert after_buy.available_cash == Decimal("595.18")
    assert after_buy.payables == Decimal("404.82")
    assert final_settlement.trade_date_cash == Decimal("1034.04")
    assert final_settlement.settled_cash == Decimal("1034.04")
    assert final_settlement.available_cash == Decimal("1034.04")
    assert final_settlement.receivables == 0
    assert final_settlement.payables == 0
    assert all(
        obligation.status is SettlementStatus.SETTLED for obligation in final_settlement.obligations
    )
    assert run.trace.final_account.cash - final_settlement.available_cash == Decimal("10")

    kinds = {entry.entry_kind for entry in run.report.ledger_trace}
    assert {
        LedgerEntryKind.CASH_FLOW.value,
        LedgerEntryKind.EXECUTION.value,
        LedgerEntryKind.STOCK_SPLIT.value,
        LedgerEntryKind.CASH_DIVIDEND_ACCRUAL.value,
        LedgerEntryKind.CASH_DIVIDEND_PAYMENT.value,
        LedgerEntryKind.SETTLEMENT_RECLASSIFICATION.value,
        LedgerEntryKind.EXECUTION_SETTLEMENT.value,
    }.issubset(kinds)


def test_golden_run_repeats_with_exact_identity_and_immutable_trace() -> None:
    first = run_golden_backtest()
    repeated = run_golden_backtest()

    assert repeated == first
    assert repeated.semantic_sha256 == first.semantic_sha256
    assert repeated.economic_identity == first.economic_identity
    assert repeated.trace.targets == first.trace.targets
    assert repeated.trace.intent_batches == first.trace.intent_batches
    assert repeated.trace.order_states == first.trace.order_states
    assert repeated.trace.execution_ledger == first.trace.execution_ledger
    assert repeated.manifest.run_id == first.manifest.run_id
    with pytest.raises(FrozenInstanceError):
        first.report.metrics = repeated.report.metrics  # type: ignore[misc]


def test_shifting_future_correction_preserves_every_earlier_decision_and_order() -> None:
    baseline = run_golden_backtest(future_correction_delay=timedelta(seconds=2))
    shifted = run_golden_backtest(future_correction_delay=timedelta(seconds=4))

    assert baseline.trace.market_events[-1].available_at != (
        shifted.trace.market_events[-1].available_at
    )
    assert baseline.trace.replay.semantic_sha256 != shifted.trace.replay.semantic_sha256
    assert baseline.trace.strategy_steps[:3] == shifted.trace.strategy_steps[:3]
    assert baseline.trace.targets == shifted.trace.targets
    assert baseline.trace.intent_batches == shifted.trace.intent_batches
    assert baseline.trace.risk_decisions == shifted.trace.risk_decisions
    assert tuple(result.submission for result in baseline.trace.broker_results) == tuple(
        result.submission for result in shifted.trace.broker_results
    )
    assert baseline.trace.broker_results[0].order_state == (
        shifted.trace.broker_results[0].order_state
    )

    # The shifted future source changes later proof identity, but never economics.
    assert baseline.trace.broker_results[1].order_state != (
        shifted.trace.broker_results[1].order_state
    )
    assert baseline.report.metrics == shifted.report.metrics
    assert (
        baseline.trace.final_account.cash == shifted.trace.final_account.cash == Decimal("1044.04")
    )
    assert baseline.report.report_sha256 != shifted.report.report_sha256


def test_generation_time_changes_artifact_not_economic_identity() -> None:
    baseline = run_golden_backtest()
    later = run_golden_backtest(generated_at=baseline.report.generated_at + timedelta(seconds=1))

    assert later.trace == baseline.trace
    assert later.report.report_sha256 == baseline.report.report_sha256
    assert later.report.artifact_sha256 != baseline.report.artifact_sha256
    assert later.manifest.run_id != baseline.manifest.run_id


@pytest.mark.parametrize(
    "delay",
    (timedelta(0), timedelta(seconds=6)),
)
def test_future_correction_must_remain_inside_its_pinned_slice(delay: timedelta) -> None:
    with pytest.raises(ValueError, match="inside its pinned watermark"):
        run_golden_backtest(future_correction_delay=delay)
