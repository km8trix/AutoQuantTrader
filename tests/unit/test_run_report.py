"""Source-bound report assembly and separate attempt identity."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from packages.application.personal_inputs import synthetic_engine_inputs
from packages.application.run_report import build_report_artifact, build_run_report
from packages.domain.accounting_contracts import AccountingState
from packages.domain.engine_contracts import DailyStrategyState
from packages.domain.metrics import ReportInputError
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.report_contracts import EngineResult
from tests.unit.test_personal_metrics import (
    CONVENTIONS,
    HASH,
    START,
    benchmark_inputs,
    interval,
    valuation,
)


def engine_result() -> EngineResult:
    names = (
        "actions",
        "availability",
        "benchmark",
        "dependency_lock",
        "dirty_patch",
        "engine",
        "numeric",
        "report",
        "source",
        "tzdata",
    )
    pins = tuple(
        VersionPin(name, "personal-report/2" if name == "report" else "fixture-v1", HASH)
        for name in names
    )
    inputs = synthetic_engine_inputs(fixture="flat", pins=pins, session_count=2, warmup_count=0)
    days = inputs.spec.evaluation.scored_sessions
    baseline = valuation(0, "1000", roles=("baseline",))
    first = valuation(1, "1000", day=1)
    terminal = valuation(2, "1000", day=2, roles=("daily_close", "terminal"))

    def at(row, day):
        moment = START.replace(year=day.year, month=day.month, day=day.day)
        return replace(
            row,
            session=day,
            economic_at=moment,
            snapshot=replace(row.snapshot, point=replace(row.snapshot.point, knowledge_at=moment)),
        )

    baseline = at(baseline, days[0] - timedelta(days=1))
    first, terminal = at(first, days[0]), at(terminal, days[1])
    rows = (baseline, first, terminal)
    spec = replace(inputs.spec, account_id="account", initial_cash=Decimal(1000))
    window = replace(interval(rows), fold_id=spec.evaluation.fold_id)
    return EngineResult(
        spec,
        "completed",
        (),
        AccountingState("account"),
        terminal.snapshot,
        DailyStrategyState(),
        rows,
        (),
        (),
        (),
        (),
        benchmark_inputs(rows, ("100", "100", "100")),
        window,
    )


def test_completed_report_retains_exact_source_and_separates_artifact_identity() -> None:
    source = engine_result()
    report = build_run_report(source, CONVENTIONS)
    assert report.source is source
    assert report.result_sha256 == source.semantic_sha256
    assert report.run_id == source.run_id
    assert report.status == "completed"
    assert {m.name: m.value for m in report.metrics}["total_return"] == 0
    assert "source-class:synthetic_fixture" in report.limitations
    generated = source.valuations[-1].snapshot.point.knowledge_at + timedelta(seconds=1)
    first = build_report_artifact(report, attempt_id="attempt-a", generated_at=generated)
    second = build_report_artifact(
        report, attempt_id="attempt-b", generated_at=generated + timedelta(seconds=1)
    )
    assert first.report.semantic_sha256 == second.report.semantic_sha256
    assert first.semantic_sha256 != second.semantic_sha256
    with pytest.raises(ReportInputError, match="predates"):
        build_report_artifact(
            report, attempt_id="attempt-a", generated_at=generated - timedelta(days=10)
        )


@pytest.mark.parametrize("status", ["cancelled", "failed", "rejected"])
def test_incomplete_attempt_preserves_financial_facts_and_reasons(status: str) -> None:
    source = replace(engine_result(), status=status, reasons=("unsupported_action",))
    report = build_run_report(source, CONVENTIONS)
    assert report.status == "incomplete"
    assert report.reasons == ("incomplete_attempt", "unsupported_action")
    assert {m.name: m.value for m in report.metrics}["ending_trade_date_cash"] == 1000


def test_custom_conventions_must_change_runspec_identity() -> None:
    source = engine_result()
    custom = replace(CONVENTIONS, minimum_annualized_sessions=300)
    with pytest.raises(ReportInputError, match="exact RunSpec pin"):
        build_run_report(source, custom)
    pin = VersionPin("report_conventions", custom.version, custom.semantic_sha256)
    spec = replace(
        source.spec, pins=tuple(sorted((*source.spec.pins, pin), key=lambda value: value.name))
    )
    changed = replace(source, spec=spec)
    assert changed.run_id != source.run_id
    assert build_run_report(changed, custom).conventions == custom
    with pytest.raises(ReportInputError, match="differ from RunSpec"):
        build_run_report(changed, CONVENTIONS)


@pytest.mark.parametrize("field", ["nav", "settled_cash"])
def test_builder_rejects_contradictory_accepted_nav_classifications(field: str) -> None:
    source = engine_result()
    last = source.valuations[-1]
    changed = replace(last, snapshot=replace(last.snapshot, **{field: Decimal(999)}))
    source = replace(source, valuations=(*source.valuations[:-1], changed))
    with pytest.raises(ReportInputError, match="do not reconcile"):
        build_run_report(source, CONVENTIONS)


def test_report_semantics_change_with_real_input_and_limitation_pins() -> None:
    source = engine_result()
    first = build_run_report(source, CONVENTIONS)
    spec = replace(
        source.spec,
        dataset_sha256=content_digest("different-dataset"),
        limitations=("exploratory",),
    )
    changed = build_run_report(replace(source, spec=spec), CONVENTIONS)
    assert changed.run_id != first.run_id
    assert changed.semantic_sha256 != first.semantic_sha256
    assert "exploratory" in changed.limitations


def test_failed_before_first_valuation_publishes_only_incomplete_reasoned_report() -> None:
    source = replace(
        engine_result(),
        status="failed",
        valuations=(),
        benchmark_inputs=(),
        reasons=("source_failure",),
    )
    report = build_run_report(source, CONVENTIONS)
    assert report.status == "incomplete"
    assert {m.name: m for m in report.metrics}["total_return"].value is None
    with pytest.raises(ReportInputError, match="omits"):
        build_run_report(replace(source, status="completed"), CONVENTIONS)
