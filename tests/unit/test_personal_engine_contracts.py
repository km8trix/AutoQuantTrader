from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import ROUND_DOWN, Decimal, localcontext

import pytest

from packages.domain.accounting_contracts import (
    AccountingCommand,
    ControlCommand,
    ExecutionPolicy,
    SettlementCalendar,
)
from packages.domain.engine_contracts import (
    DailyPrice,
    DailyRiskPolicy,
    EngineEvent,
    ObservationProvenance,
)
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.personal_contracts import content_digest
from packages.domain.report_contracts import ExternalFlowRow, ReportConventions
from packages.domain.research_dataset import ResearchDataClass

AT = datetime(2025, 1, 2, 21, tzinfo=UTC)
D = Decimal


def test_union_records_accept_exact_payload_and_reject_mutable_or_wrong_shape():
    command = AccountingCommand("control-1", ControlCommand(True, "owner halt"))
    assert len(command.semantic_sha256) == 64
    with pytest.raises(ValueError):
        AccountingCommand("wrong", {"halted": True})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ControlCommand(1, "not a boolean")  # type: ignore[arg-type]


def _event():
    price = DailyPrice("spy", "SPY", date(2025, 1, 2), D("100"), D("101"), D("101"))
    provenance = ObservationProvenance(
        ResearchDataClass.SYNTHETIC_FIXTURE,
        "fixture",
        content_digest(price),
        simulated_available_at=AT,
        assumption_id="modeled-fixture/1",
        raw_sha256="a" * 64,
    )
    return EngineEvent("price-1", AT, AT, price, provenance)


def test_raw_file_future_content_changes_full_identity_but_not_causal_content():
    first = _event()
    second = replace(first, provenance=replace(first.provenance, raw_sha256="b" * 64))
    assert first.semantic_sha256 != second.semantic_sha256
    assert first.causal_sha256 == second.causal_sha256
    changed = replace(first.payload, close_price=D("102"))
    with pytest.raises(ValueError, match="normalized provenance"):
        replace(first, payload=changed)


def test_identity_is_independent_of_ambient_decimal_precision():
    event = _event()
    expected = event.semantic_sha256
    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        assert event.semantic_sha256 == expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_gross_nav_fraction", D("1")),
        ("max_order_nav_fraction", D("0.26")),
        ("max_symbol_nav_fraction", D("0.26")),
        ("max_open_intents", 5),
        ("adverse_reserve_fraction", D("0")),
        ("max_new_intents_per_session", 9),
    ],
)
def test_product_risk_cannot_silently_expand_frozen_scope(field, value):
    with pytest.raises(ValueError):
        replace(DailyRiskPolicy(), **{field: value})


def test_synthetic_oracle_is_an_explicit_distinct_policy():
    policy = DailyRiskPolicy()
    oracle = replace(
        policy,
        policy_id="hand-calculated-oracle/1",
        policy_scope="synthetic_oracle",
        max_order_nav_fraction=D(1),
    )
    assert oracle.semantic_sha256 != policy.semantic_sha256


def test_settlement_calendar_is_separate_content_and_requires_explicit_dates():
    calendar = SettlementCalendar("synthetic-settlement", "1", (date(2025, 1, 3), date(2025, 1, 6)))
    policy = ExecutionPolicy(calendar)
    changed = replace(
        policy, settlement_calendar=replace(calendar, business_dates=(date(2025, 1, 6),))
    )
    assert policy.semantic_sha256 != changed.semantic_sha256
    with pytest.raises(ValueError):
        replace(calendar, business_dates=(date(2025, 1, 6), date(2025, 1, 3)))


def _flow(kind, signed, origin="external_flow"):
    fact = create_cash_flow(
        kind=kind,
        currency="USD",
        amount=D("1234.56789"),
        effective_at=AT,
        recorded_at=AT,
        external_reference="synthetic-flow",
    )
    return ExternalFlowRow(fact, signed, 1, "before", "after", origin, "c" * 64)


def test_flow_sign_is_bound_to_actual_fact_and_initial_funding_is_positive():
    with pytest.raises(ValueError, match="direction"):
        _flow(CashFlowKind.WITHDRAWAL, D("1234.56789"))
    with pytest.raises(ValueError, match="initial capital"):
        _flow(CashFlowKind.WITHDRAWAL, D("-1234.56789"), "initial_capital")
    first = _flow(CashFlowKind.WITHDRAWAL, D("-1234.56789"))
    with localcontext() as context:
        context.prec = 2
        assert (
            _flow(CashFlowKind.WITHDRAWAL, D("-1234.56789")).semantic_sha256
            == first.semantic_sha256
        )


def test_report_conventions_bind_unknown_and_zero_risk_free_values():
    with pytest.raises(ValueError):
        ReportConventions(risk_free_daily=None)
    unavailable = ReportConventions(risk_free_daily=None, risk_free_model="unavailable")
    assert unavailable.semantic_sha256 != ReportConventions().semantic_sha256
