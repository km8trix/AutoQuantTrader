"""Presentation tests over actual W2 engine reports; job envelopes are explicit fixtures."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, Inexact, Rounded, localcontext

import pytest

from apps.api import personal_research_projection as projection
from apps.api.personal_research_projection import (
    PersonalProjectionError,
    comparison_view,
    configuration_view,
    report_rows,
    report_view,
    run_view,
)
from packages.application.personal_codec import encode_record
from packages.application.run_report import build_run_report
from packages.domain.accounting_contracts import AccountingCommand
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import BenchmarkPrice, DailyPrice
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.personal_contracts import CausalMark, content_digest
from packages.domain.report_contracts import ReportArtifact, ReportConventions
from packages.domain.research_job_contracts import (
    ObjectRef,
    ResearchAttempt,
    ResearchJobView,
    ResearchProgress,
    ResearchPublication,
    ResearchRunRequest,
)
from tests.integration.test_personal_evaluation_engine import run
from tests.unit.test_causal_engine import event, with_events
from tests.unit.test_personal_evaluation import source_inputs

D = Decimal
AT = datetime(2026, 9, 9, tzinfo=UTC)


def object_ref(value):
    body = encode_record(value)
    return ObjectRef(hashlib.sha256(body).hexdigest(), len(body))


def inputs_for(*, cost="base_1x", kind="buy_hold", fixture="flat"):
    source = source_inputs(fixture)
    configuration = ReferenceConfiguration(kind, 2)
    bps, fee = {"base_1x": (D(5), D(".01")), "adverse": (D(20), D(".02"))}[cost]
    return replace(
        source,
        spec=replace(
            source.spec,
            max_cpu_cores=1,
            max_memory_bytes=4 * 1024**3,
            max_output_bytes=64 * 1024**2,
            strategy_configuration=configuration,
            strategy=replace(
                source.spec.strategy,
                sha256=content_digest((configuration, "reference-callback-adapter/1")),
            ),
            execution_policy=replace(
                source.spec.execution_policy, slippage_bps=bps, fee_per_share=fee
            ),
            risk_policy=replace(source.spec.risk_policy, fee_per_share=fee),
        ),
    )


def published(inputs, *, name="projection-test", report=None):
    # The engine computes economics. These exact DTO envelopes are test fixtures,
    # not a claim that a durable A worker ran inside this unit test.
    report = report or build_run_report(run(inputs), ReportConventions())
    request = ResearchRunRequest(
        inputs.spec,
        report.conventions,
        object_ref(inputs),
        "test-owner",
        name,
        "projection-trial",
        settlement_calendar=object_ref(inputs.spec.execution_policy.settlement_calendar),
    )
    artifact = ReportArtifact(report, content_digest((name, "attempt")), AT + timedelta(seconds=1))
    publication = ResearchPublication(
        request.job_id,
        request.run_id,
        artifact.attempt_id,
        report.status,
        report.result_sha256,
        report.semantic_sha256,
        artifact.semantic_sha256,
        object_ref(artifact),
    )
    job = ResearchJobView(
        request.job_id,
        request.run_id,
        request.owner_id,
        request.trial_id,
        report.status,
        AT,
        AT + timedelta(seconds=2),
        False,
        (ResearchAttempt(artifact.attempt_id, 1, AT, AT + timedelta(seconds=2), report.status),),
        "a" * 64,
        publication=publication,
    )
    return request, job, artifact


def rows(job, artifact, kind, **kwargs):
    return report_rows(
        job,
        artifact,
        kind=kind,
        report_sha256=artifact.report.semantic_sha256,
        offset=kwargs.get("offset", 0),
        limit=kwargs.get("limit", 200),
    )


def test_actual_report_run_and_row_projections_preserve_source_values():
    request, job, artifact = published(inputs_for())
    view = run_view(request, job, cost_scenario_id="base_1x")
    assert view.dataset_id == request.spec.dataset_id and view.status == "completed"
    assert view.configuration == configuration_view(request.spec.strategy_configuration)
    report = report_view(request, job, artifact)
    source_metrics = {m.name: m for m in artifact.report.metrics}
    assert all(m.value == source_metrics[m.name].value for m in report.metrics)
    assert next(m.value for m in report.metrics if m.name == "ending_equity") == D("9998.56")
    assert report.report_sha256 == artifact.report.semantic_sha256
    assert report.benchmark_name == artifact.report.benchmark.model and report.export_url is None
    assert (
        next(p.value for p in report.provenance if p.name == "journal_sequence_basis")
        == "canonical-journal-tuple-index"
    )
    executions = rows(job, artifact, "executions")
    assert executions.total == 1 and executions.rows[0].fee == D(".24")
    assert executions.rows[0].source_row_ids == [artifact.report.source.executions[0].fact_id]
    position = rows(job, artifact, "positions").rows[0]
    assert position.quantity == 24 and position.market_value == 2400 and position.mark == 100
    assert position.unrealized_pnl == D("-1.2")
    equity = rows(job, artifact, "equity")
    assert equity.total == len(artifact.report.source.valuations)
    assert equity.rows[-1].nav == artifact.report.source.final_snapshot.nav
    assert equity.rows[-1].wealth == artifact.report.returns[-1].wealth
    journal = rows(job, artifact, "journal")
    assert [r.entry_id for r in journal.rows] == [
        r.entry_id for r in artifact.report.source.journal_entries
    ]
    assert [r.sequence for r in journal.rows] == list(range(journal.total))
    assert rows(job, artifact, "equity", offset=1, limit=2).rows == equity.rows[1:3]
    assert rows(job, artifact, "equity", offset=1000).rows == []
    assert '"value":"9998.56"' in report.model_dump_json()


def test_pagination_materializes_only_the_requested_api_rows(monkeypatch):
    _, job, artifact = published(inputs_for())
    constructor = projection.PersonalEquityRow
    created = []

    def counted(**kwargs):
        created.append(kwargs["row_id"])
        return constructor(**kwargs)

    monkeypatch.setattr(projection, "PersonalEquityRow", counted)
    page = rows(job, artifact, "equity", offset=2, limit=1)
    assert page.total > 3 and len(page.rows) == len(created) == 1
    created.clear()
    assert rows(job, artifact, "equity", offset=page.total + 1, limit=1).rows == []
    assert created == []


@pytest.mark.parametrize(
    "change", ("report", "result", "artifact", "object", "attempt", "run", "request")
)
def test_publication_bindings_must_match_before_any_projection(change):
    request, job, artifact = published(inputs_for())
    publication = job.publication
    assert publication is not None
    if change in ("report", "result", "artifact"):
        publication = replace(publication, **{change + "_sha256": "b" * 64})
    elif change == "object":
        publication = replace(
            publication, object=replace(publication.object, object_sha256="b" * 64)
        )
    elif change == "attempt":
        job = replace(job, attempts=(replace(job.attempts[0], attempt_id="b" * 64),))
    elif change == "run":
        job = replace(job, run_id="run-" + "b" * 64)
    else:
        request = replace(request, spec=replace(request.spec, initial_cash=D(20000)))
    job = replace(job, publication=publication)
    with pytest.raises(PersonalProjectionError):
        report_view(request, job, artifact)
    if change != "request":
        with pytest.raises(PersonalProjectionError):
            rows(job, artifact, "equity")


@pytest.mark.parametrize(
    "kwargs",
    (
        {"report_sha256": "c" * 64},
        {"offset": True},
        {"offset": -1},
        {"limit": True},
        {"limit": 0},
        {"limit": 201},
        {"kind": "other"},
    ),
)
def test_pagination_is_bounded_and_pinned_to_exact_report(kwargs):
    _, job, artifact = published(inputs_for())
    params = {
        "kind": "equity",
        "report_sha256": artifact.report.semantic_sha256,
        "offset": 0,
        "limit": 10,
    }
    params.update(kwargs)
    with pytest.raises(PersonalProjectionError):
        report_rows(job, artifact, **params)


def test_running_progress_has_no_invented_total_and_retains_abandoned_attempt():
    request, job, _ = published(inputs_for())
    first = replace(job.attempts[0], outcome="abandoned", reason_code="worker_shutdown")
    current = ResearchAttempt("b" * 64, 2, AT + timedelta(seconds=3), None, "running")
    running = replace(
        job,
        status="running",
        publication=None,
        attempts=(first, current),
        progress=ResearchProgress("running", processed_events=17),
    )
    view = run_view(request, running, cost_scenario_id="base_1x")
    assert (
        view.progress_completed == 17
        and view.progress_total is None
        and view.progress_unit == "events"
    )
    assert [a.status for a in view.attempts] == ["abandoned", "running"]
    assert view.attempts[0].reasons == ["worker_shutdown"]
    with pytest.raises(PersonalProjectionError):
        run_view(request, running, cost_scenario_id="adverse")


def test_actual_missing_terminal_close_preserves_nulls_and_estimate_without_stale_position_mark():
    inputs = inputs_for()
    missing = inputs.spec.evaluation.scored_sessions[-1]
    inputs = with_events(
        inputs,
        tuple(
            e
            for e in inputs.events
            if not (isinstance(e.payload, DailyPrice) and e.payload.session == missing)
        ),
    )
    request, job, artifact = published(inputs)
    # Publication completion and metric availability are separate: preserve
    # the actual report status while exposing the missing valuation.
    equity = rows(job, artifact, "equity")
    last = equity.rows[-1]
    assert last.nav is None and last.wealth is None and last.drawdown is None
    assert last.last_known_nav == D("9998.56") and last.reasons
    positions = rows(job, artifact, "positions").rows
    assert positions[0].mark is positions[0].market_value is positions[0].unrealized_pnl is None
    assert positions[0].reasons
    assert report_view(request, job, artifact).status == artifact.report.status


def test_actual_recovered_nav_does_not_repair_the_return_path_missingness_latch():
    inputs = inputs_for()
    missing = inputs.spec.evaluation.scored_sessions[-2]
    inputs = with_events(
        inputs,
        tuple(
            e
            for e in inputs.events
            if not (isinstance(e.payload, DailyPrice) and e.payload.session == missing)
        ),
    )
    _, job, artifact = published(inputs)
    equity = rows(job, artifact, "equity").rows
    hole = next(r for r in equity if r.session == missing and "daily_close" in r.roles)
    assert hole.nav is None and hole.wealth is None
    assert equity[-1].nav is not None and equity[-1].wealth is None
    assert equity[-1].drawdown is None and equity[-1].reasons


@pytest.mark.parametrize("exact", (True, False))
def test_actual_flow_pair_rows_match_ids_and_post_only_signed_flow(exact):
    inputs = inputs_for()
    session = inputs.spec.evaluation.scored_sessions[2]
    at = next(
        s.opens_at for s in inputs.spec.calendar.sessions if s.session_label == session
    ) + timedelta(minutes=30)
    mark_at = at if exact else at - timedelta(minutes=10)
    instrument, symbol = inputs.spec.instruments[0]
    mark = CausalMark(
        "flow-mark",
        instrument,
        symbol,
        D(100),
        session,
        mark_at,
        mark_at,
        "d" * 64,
        basis="synthetic_boundary",
    )
    mark_event = event(inputs, "flow-mark", AccountingCommand("flow-mark", mark), mark_at, mark_at)
    benchmark = event(
        inputs,
        "flow-benchmark",
        BenchmarkPrice("SPY-total-return-units/1", D(100), "synthetic_total_return_units"),
        at,
        at,
    )
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=D(500),
        effective_at=at,
        recorded_at=at,
        external_reference="projection-flow",
    )
    flow_event = event(
        inputs,
        "projection-flow",
        AccountingCommand("projection-flow", flow),
        at,
        at,
        (mark_event.event_id, benchmark.event_id),
    )
    inputs = with_events(inputs, (*inputs.events, mark_event, benchmark, flow_event))
    _, job, artifact = published(inputs)
    projected = rows(job, artifact, "equity").rows
    pair = [r for r in projected if r.flow_id == flow.cash_flow_id]
    assert (
        len(pair) == 2
        and pair[0].paired_row_id == pair[1].row_id
        and pair[1].paired_row_id == pair[0].row_id
    )
    assert [r.signed_flow for r in pair] == [0, 500]
    if exact:
        assert [r.nav for r in pair] == [D("9998.56"), D("10498.56")]
        assert pair[0].wealth == pair[1].wealth
    else:
        assert all(r.nav is None and r.wealth is None for r in pair)
        assert [r.last_known_nav for r in pair] == [D("9998.56"), D("10498.56")]
        assert pair[1].last_known_at is None


def test_actual_fifo_groups_preserve_effective_ids_fees_under_hostile_decimal_context():
    _, job, artifact = published(inputs_for(kind="trend_sma", fixture="regime"))
    matches = artifact.report.source.fifo_matches
    assert matches and any(m.group_complete for m in matches)
    projected = rows(job, artifact, "fifo")
    with localcontext() as context:
        context.prec = 2
        context.traps[Inexact] = context.traps[Rounded] = True
        assert rows(job, artifact, "fifo") == projected
    assert {i for r in projected.rows for i in r.match_ids} == {m.match_id for m in matches}
    for row in projected.rows:
        group = [m for m in matches if m.closing_order_id == row.closing_order_id]
        assert row.buy_fees == sum(m.opening_fee for m in group)
        assert row.sell_fees == sum(m.closing_fee for m in group)
        assert row.net_pnl == sum(
            m.proceeds - m.basis - m.opening_fee - m.closing_fee for m in group
        )


def test_comparison_accepts_only_equal_basis_while_listing_actual_cost_and_configuration():
    base = published(inputs_for(), name="base-comparison")
    adverse = published(inputs_for(cost="adverse"), name="adverse-comparison")
    trend = published(inputs_for(kind="trend_sma"), name="trend-comparison")
    view = comparison_view(((*base, "base_1x"), (*adverse, "adverse"), (*trend, "base_1x")))
    assert view.comparable and not view.reasons and len(view.runs) == 3
    assert len(view.differences) == 6
    assert [v.cost_scenario_id for v in view.runs] == ["base_1x", "adverse", "base_1x"]
    changed = inputs_for()
    changed = replace(changed, spec=replace(changed.spec, initial_cash=D(20000)))
    other = published(changed, name="changed-capital")
    mismatch = comparison_view(((*base, "base_1x"), (*other, "base_1x")))
    assert not mismatch.comparable and "comparison_basis_differs:initial_cash" in mismatch.reasons
    with pytest.raises(PersonalProjectionError):
        comparison_view(((*base, "base_1x"), (*base, "base_1x")))


def test_metric_lineage_has_explicit_bounded_presentation_flag():
    inputs = inputs_for()
    report = build_run_report(run(inputs), ReportConventions())
    # A declared long-lineage fixture tests clipping only; economics remain the
    # actual small engine report and no claim is made that 201 sessions ran.
    metric = report.metrics[0]
    coverage = replace(
        metric.coverage,
        contributing_row_ids=tuple(f"declared-{i}" for i in range(201)),
        excluded=tuple((f"excluded-{i}", ("projection-bound-fixture",)) for i in range(201)),
    )
    report = replace(report, metrics=(replace(metric, coverage=coverage), *report.metrics[1:]))
    request, job, artifact = published(inputs, report=report)
    view = report_view(request, job, artifact)
    assert view.metrics[0].coverage.lineage_truncated
    assert (
        len(view.metrics[0].coverage.contributing_row_ids)
        == len(view.metrics[0].coverage.excluded)
        == 200
    )
