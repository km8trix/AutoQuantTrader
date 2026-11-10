"""Pure bounded browser views of retained research publications and source rows."""

from __future__ import annotations

import hashlib
from dataclasses import fields, replace
from datetime import datetime
from decimal import Decimal, localcontext
from typing import Literal, cast

from apps.api.personal_research_contracts import (
    PersonalAttemptView,
    PersonalComparison,
    PersonalComparisonItem,
    PersonalConfiguration,
    PersonalCoverageExclusion,
    PersonalEquityRow,
    PersonalExecutionRow,
    PersonalFifoRow,
    PersonalJournalRow,
    PersonalMetric,
    PersonalMetricCoverage,
    PersonalNamedValue,
    PersonalPositionRow,
    PersonalReportInterval,
    PersonalReportRow,
    PersonalRowsKind,
    PersonalRunReport,
    PersonalRunRows,
    PersonalRunView,
)
from packages.application.personal_codec import encode_record
from packages.domain.accounting_contracts import AccountSnapshot, FifoMatchRow
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.decimal_math import exact_decimal_multiply, exact_decimal_subtract
from packages.domain.personal_contracts import content_digest
from packages.domain.personal_evaluation import COST_SCENARIOS
from packages.domain.report_contracts import MetricValue, ReportArtifact, RunReport, ScoredInterval
from packages.domain.research_job_contracts import ResearchJobView, ResearchRunRequest
from packages.domain.wealth import derived_context


class PersonalProjectionError(ValueError):
    """The requested view is not bound to its exact retained publication."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PersonalProjectionError(message)


def _plain(value: object) -> str:
    return format(value, "f") if isinstance(value, Decimal) else str(value)


def configuration_view(configuration: ReferenceConfiguration) -> PersonalConfiguration:
    _require(
        type(configuration) is ReferenceConfiguration, "exact reference configuration required"
    )
    return PersonalConfiguration(
        kind=cast(Literal["buy_hold", "trend_sma"], configuration.kind),
        lookback=configuration.lookback,
        allocation=_plain(configuration.allocation),
        rebalance_sessions=configuration.rebalance_sessions,
    )


def _job(request: ResearchRunRequest, job: ResearchJobView) -> None:
    _require(
        type(request) is ResearchRunRequest and type(job) is ResearchJobView,
        "exact retained request and job view required",
    )
    _require(
        (job.job_id, job.run_id, job.owner_id, job.trial_id)
        == (request.job_id, request.run_id, request.owner_id, request.trial_id),
        "job view differs from accepted request",
    )
    _require(
        (job.publication is not None) == (job.status in ("completed", "incomplete")),
        "job publication and terminal status disagree",
    )
    if job.publication is not None:
        _require(
            (job.publication.job_id, job.publication.run_id, job.publication.outcome)
            == (job.job_id, job.run_id, job.status),
            "job publication identity differs",
        )


def _cost(request: ResearchRunRequest, identity: str) -> None:
    scenario = next((c for c in COST_SCENARIOS if c.scenario_id == identity), None)
    _require(
        scenario is not None
        and (
            request.spec.execution_policy.slippage_bps,
            request.spec.execution_policy.fee_per_share,
        )
        == (scenario.slippage_bps, scenario.fee_per_share),
        "cost scenario label differs from executed model",
    )


def run_view(
    request: ResearchRunRequest, job: ResearchJobView, *, cost_scenario_id: str
) -> PersonalRunView:
    _job(request, job)
    _cost(request, cost_scenario_id)
    spec, publication, progress = request.spec, job.publication, job.progress
    return PersonalRunView(
        job_id=job.job_id,
        run_id=job.run_id,
        spec_sha256=spec.semantic_sha256,
        dataset_id=spec.dataset_id,
        dataset_manifest_sha256=spec.dataset_sha256,
        data_class=spec.data_class.value,
        strategy_id=spec.strategy_configuration.kind,
        strategy_version=spec.strategy.version,
        configuration=configuration_view(spec.strategy_configuration),
        cost_scenario_id=cost_scenario_id,
        status=job.status,
        cancel_requested=job.cancel_requested,
        requested_at=job.requested_at,
        updated_at=job.updated_at,
        progress_completed=None if progress is None else progress.processed_events,
        progress_total=None,
        progress_unit=None if progress is None or progress.processed_events is None else "events",
        attempts=[
            PersonalAttemptView(
                attempt_id=a.attempt_id,
                attempt_number=a.attempt_number,
                status=a.outcome,
                started_at=a.started_at,
                ended_at=a.ended_at,
                reasons=[] if a.reason_code is None else [a.reason_code],
            )
            for a in job.attempts
        ],
        report_sha256=None if publication is None else publication.report_sha256,
        result_sha256=None if publication is None else publication.result_sha256,
        reasons=[] if job.reason_code is None else [job.reason_code],
        limitations=list(spec.limitations),
    )


def _published(
    job: ResearchJobView, artifact: ReportArtifact, request: ResearchRunRequest | None = None
) -> RunReport:
    _require(
        type(job) is ResearchJobView and type(artifact) is ReportArtifact,
        "exact job and published artifact required",
    )
    if request is not None:
        _job(request, job)
    publication = job.publication
    _require(
        publication is not None and job.status in ("completed", "incomplete"),
        "job has no retained report publication",
    )
    assert publication is not None
    report, result = artifact.report, artifact.report.source
    _require(
        (publication.job_id, publication.run_id, publication.outcome, publication.attempt_id)
        == (job.job_id, job.run_id, job.status, artifact.attempt_id),
        "publication job/run/attempt differs",
    )
    _require(
        bool(job.attempts)
        and job.attempts[-1].attempt_id == artifact.attempt_id
        and job.attempts[-1].outcome == job.status
        and job.attempts[-1].ended_at is not None,
        "publication lacks the matching terminal attempt",
    )
    _require(
        report.run_id == result.spec.run_id == job.run_id
        and report.status == job.status
        and (report.status == "completed") == (result.status == "completed")
        and report.result_sha256 == result.semantic_sha256
        and report.interval == result.interval
        and publication.result_sha256 == report.result_sha256
        and publication.report_sha256 == report.semantic_sha256
        and publication.artifact_sha256 == artifact.semantic_sha256,
        "artifact/report/result identities differ from publication",
    )
    _require(
        request is None
        or (request.spec == result.spec and request.conventions == report.conventions),
        "report specification or conventions differ from request",
    )
    payload = encode_record(artifact)
    _require(
        publication.object.codec_version == "personal-record/1"
        and publication.object.byte_count == len(payload)
        and publication.object.object_sha256 == hashlib.sha256(payload).hexdigest(),
        "published object bytes differ from artifact",
    )
    return report


def _metric(value: MetricValue) -> PersonalMetric:
    c = value.coverage
    return PersonalMetric(
        name=value.name,
        value=value.value,
        unit=value.unit,
        status=value.status,
        coverage=PersonalMetricCoverage(
            interval_id=c.interval_id,
            expected_sessions=c.expected_sessions,
            observed_sessions=c.observed_sessions,
            valid_sessions=c.valid_sessions,
            valid_returns=c.valid_returns,
            sample_count=c.sample_count,
            input_sha256=c.input_sha256,
            contributing_row_ids=list(c.contributing_row_ids[:200]),
            excluded=[
                PersonalCoverageExclusion(row_id=i, reasons=list(r)) for i, r in c.excluded[:200]
            ],
            lineage_truncated=len(c.contributing_row_ids) > 200 or len(c.excluded) > 200,
        ),
        conventions_sha256=value.conventions_sha256,
        reasons=list(value.reasons),
        assumptions=list(value.assumptions),
    )


def _interval(interval: ScoredInterval) -> PersonalReportInterval:
    scored, warmup = interval.expected_sessions, interval.warmup_sessions
    return PersonalReportInterval(
        interval_id=interval.interval_id,
        fold_id=interval.fold_id,
        scored_start=scored[0] if scored else None,
        scored_end=scored[-1] if scored else None,
        warmup_start=warmup[0] if warmup else None,
        warmup_end=warmup[-1] if warmup else None,
        expected_sessions=len(scored),
        reset_mode=interval.reset_mode,
        baseline_valuation_id=interval.baseline_valuation_id,
        terminal_valuation_id=interval.terminal_valuation_id,
    )


def _assumptions(report: RunReport) -> list[str]:
    return sorted(
        {
            a
            for m in (*report.metrics, *report.benchmark.metrics, *report.benchmark.cash_metrics)
            for a in m.assumptions
        }
    )


def report_view(
    request: ResearchRunRequest, job: ResearchJobView, artifact: ReportArtifact
) -> PersonalRunReport:
    report = _published(job, artifact, request)
    spec = request.spec
    provenance = {
        "dataset_sha256": spec.dataset_sha256,
        "events_sha256": spec.events_sha256,
        "spec_sha256": spec.semantic_sha256,
        "calendar_sha256": report.interval.calendar_sha256,
        "availability_mode": spec.availability_mode,
        "prior_access": spec.evaluation.prior_access_label,
        "journal_sequence_basis": "canonical-journal-tuple-index",
    }
    provenance.update({"pin:" + p.name: p.version + ":" + p.sha256 for p in spec.pins})
    return PersonalRunReport(
        job_id=job.job_id,
        run_id=job.run_id,
        report_sha256=report.semantic_sha256,
        result_sha256=report.result_sha256,
        artifact_sha256=artifact.semantic_sha256,
        attempt_id=artifact.attempt_id,
        generated_at=artifact.generated_at,
        status=report.status,
        currency=report.conventions.currency,
        dataset_id=spec.dataset_id,
        data_class=spec.data_class.value,
        interval=_interval(report.interval),
        metrics=[_metric(m) for m in report.metrics],
        benchmark_metrics=[_metric(m) for m in report.benchmark.metrics],
        cash_metrics=[_metric(m) for m in report.benchmark.cash_metrics],
        benchmark_name=report.benchmark.model,
        conventions=[
            PersonalNamedValue(name=f.name, value=_plain(getattr(report.conventions, f.name)))
            for f in fields(report.conventions)
        ],
        provenance=[PersonalNamedValue(name=k, value=v) for k, v in sorted(provenance.items())],
        assumptions=_assumptions(report),
        limitations=list(report.limitations),
        reasons=list(report.reasons),
        export_url=None,
    )


def _equity(report: RunReport, offset: int, limit: int) -> tuple[int, list[PersonalReportRow]]:
    valuations = sorted(report.source.valuations, key=lambda r: r.snapshot.point.reduction_sequence)
    returns = {r.valuation_id: r for r in report.returns}
    benchmark = {r.valuation_id: r for r in report.benchmark.rows}
    cash = {r.valuation_id: r for r in report.benchmark.cash_rows}
    flows = {r.post_valuation_id: r for r in report.source.flows}
    _require(
        len(returns) == len(report.returns)
        and len(benchmark) == len(report.benchmark.rows)
        and len(cash) == len(report.benchmark.cash_rows)
        and len(flows) == len(report.source.flows),
        "report row identities are not unique",
    )
    ids = {v.row_id for v in valuations}
    _require(
        len(ids) == len(valuations)
        and set(returns).issubset(ids)
        and set(benchmark).issubset(ids)
        and set(cash).issubset(ids)
        and set(flows).issubset(ids),
        "report rows do not bind exact valuation identities",
    )
    by_id = {v.row_id: v for v in valuations}
    for flow in report.source.flows:
        before, after = by_id.get(flow.pre_valuation_id), by_id.get(flow.post_valuation_id)
        _require(
            before is not None
            and after is not None
            and before.flow_id == after.flow_id == flow.flow.cash_flow_id
            and before.paired_row_id == after.row_id
            and after.paired_row_id == before.row_id
            and "pre_flow" in before.roles
            and "post_flow" in after.roles,
            "external flow lacks its exact paired valuation rows",
        )
    rows: list[PersonalReportRow] = []
    known: list[tuple[AccountSnapshot, datetime]] = []
    for index, v in enumerate(valuations[: offset + limit]):
        snapshot = v.snapshot
        if index < offset:
            if snapshot.nav is not None:
                known.append((snapshot, snapshot.point.knowledge_at))
            continue
        path, spy, bank = returns.get(v.row_id), benchmark.get(v.row_id), cash.get(v.row_id)
        last_at = (
            None
            if snapshot.last_known_nav is None
            else next(
                (
                    at
                    for prior, at in reversed(known)
                    if prior.nav == snapshot.last_known_nav
                    and (
                        prior.positions,
                        prior.marks,
                        prior.trade_date_cash,
                        prior.dividend_receivable,
                    )
                    == (
                        snapshot.positions,
                        snapshot.marks,
                        snapshot.trade_date_cash,
                        snapshot.dividend_receivable,
                    )
                ),
                None,
            )
        )
        rows.append(
            PersonalEquityRow(
                kind="equity",
                row_id=v.row_id,
                sequence=snapshot.point.reduction_sequence,
                economic_at=v.economic_at,
                knowledge_at=snapshot.point.knowledge_at,
                session=v.session,
                roles=list(v.roles),
                nav=snapshot.nav,
                wealth=None if path is None else path.wealth,
                drawdown=None if path is None else path.drawdown,
                signed_flow=flows[v.row_id].signed_amount if v.row_id in flows else Decimal(0),
                flow_id=v.flow_id,
                paired_row_id=v.paired_row_id,
                last_known_nav=snapshot.last_known_nav,
                last_known_at=last_at,
                benchmark_nav=None if spy is None else spy.nav,
                benchmark_wealth=None if spy is None else spy.wealth,
                cash_nav=None if bank is None else bank.nav,
                cash_wealth=None if bank is None else bank.wealth,
                reasons=sorted(
                    set(
                        (
                            *snapshot.valuation_reasons,
                            *(path.reasons if path else ("outside_scored_return_rows",)),
                        )
                    )
                ),
                benchmark_reasons=list(spy.reasons) if spy else ["benchmark_row_unavailable"],
                cash_reasons=list(bank.reasons) if bank else ["cash_comparator_row_unavailable"],
            )
        )
        if snapshot.nav is not None:
            known.append((snapshot, snapshot.point.knowledge_at))
    return len(valuations), rows


def _fifo(report: RunReport, offset: int, limit: int) -> tuple[int, list[PersonalReportRow]]:
    matches = report.source.fifo_matches
    executions = {(e.execution_id, e.revision): e for e in report.source.executions}
    _require(
        len(executions) == len(report.source.executions)
        and len({m.match_id for m in matches}) == len(matches),
        "effective execution/match rows are not unique",
    )
    rows: list[PersonalReportRow] = []
    groups: dict[str, list[FifoMatchRow]] = {}
    for match in matches:
        groups.setdefault(match.closing_order_id, []).append(match)
    for identity in sorted(groups)[offset : offset + limit]:
        group = groups[identity]
        _require(len({m.group_complete for m in group}) == 1, "FIFO group completion differs")
        for m in group:
            _require(
                (m.opening_execution_id, m.opening_revision) in executions
                and (m.closing_execution_id, m.closing_revision) in executions,
                "FIFO match lacks effective execution lineage",
            )
        symbol = executions[(group[0].closing_execution_id, group[0].closing_revision)].symbol
        with localcontext(derived_context()):
            quantity = sum((m.quantity for m in group), Decimal(0))
            gross = sum((m.proceeds - m.basis for m in group), Decimal(0))
            buy = sum((m.opening_fee for m in group), Decimal(0))
            sell = sum((m.closing_fee for m in group), Decimal(0))
            net = gross - buy - sell
        rows.append(
            PersonalFifoRow(
                kind="fifo",
                closing_order_id=identity,
                symbol=symbol,
                completed=group[0].group_complete,
                quantity=quantity,
                gross_pnl=gross,
                buy_fees=buy,
                sell_fees=sell,
                net_pnl=net,
                match_ids=sorted(m.match_id for m in group),
                execution_ids=sorted(
                    {i for m in group for i in (m.opening_execution_id, m.closing_execution_id)}
                ),
                split_ids=sorted({i for m in group for i in m.split_ids}),
            )
        )
    return len(groups), rows


def _positions(report: RunReport) -> list[PersonalReportRow]:
    snapshot = report.source.final_snapshot
    terminal = next(
        (v for v in report.source.valuations if v.row_id == report.interval.terminal_valuation_id),
        None,
    )
    _require(
        terminal is not None and terminal.snapshot == snapshot,
        "final positions lack the exact terminal valuation",
    )
    assert terminal is not None
    marks = {m.instrument_id: m for m in snapshot.marks}
    _require(len(marks) == len(snapshot.marks), "position marks are not unique")
    rows: list[PersonalReportRow] = []
    for p in snapshot.positions:
        mark = marks.get(p.instrument_id)
        usable = (
            mark is not None
            and mark.quality == "current"
            and mark.knowledge_at <= snapshot.point.knowledge_at
            and mark.session == terminal.session
            and not any(
                reason.endswith(":" + p.instrument_id) for reason in snapshot.valuation_reasons
            )
        )
        value = (
            exact_decimal_multiply(p.quantity, mark.price) if usable and mark is not None else None
        )
        rows.append(
            PersonalPositionRow(
                kind="positions",
                symbol=p.symbol,
                quantity=p.quantity,
                cost_basis=p.cost_basis,
                market_value=value,
                unrealized_pnl=None
                if value is None
                else exact_decimal_subtract(value, p.cost_basis),
                mark=mark.price if usable and mark is not None else None,
                mark_at=mark.economic_at if usable and mark is not None else None,
                reasons=[] if usable else ["current_position_mark_unavailable"],
            )
        )
    return rows


def report_rows(
    job: ResearchJobView,
    artifact: ReportArtifact,
    *,
    kind: PersonalRowsKind,
    report_sha256: str,
    offset: int,
    limit: int,
) -> PersonalRunRows:
    report = _published(job, artifact)
    _require(report_sha256 == report.semantic_sha256, "row pagination report digest differs")
    _require(
        type(offset) is int and offset >= 0 and type(limit) is int and 1 <= limit <= 200,
        "row pagination must use bounded integer offsets",
    )
    _require(
        kind in ("equity", "executions", "fifo", "journal", "positions"),
        "unsupported report row kind",
    )
    rows: list[PersonalReportRow]
    if kind == "equity":
        total, rows = _equity(report, offset, limit)
    elif kind == "fifo":
        total, rows = _fifo(report, offset, limit)
    elif kind == "positions":
        all_positions = _positions(report)
        total, rows = len(all_positions), all_positions[offset : offset + limit]
    elif kind == "executions":
        total = len(report.source.executions)
        rows = [
            PersonalExecutionRow(
                kind="executions",
                execution_id=e.execution_id,
                revision=e.revision,
                order_id=e.order_id,
                intent_id=e.intent_id,
                symbol=e.symbol,
                side=e.side.value,
                quantity=e.quantity,
                price=e.price,
                fee=e.fee,
                occurred_at=e.economic_at,
                source_row_ids=[
                    e.fact_id,
                    *(() if e.supersedes_fact_id is None else (e.supersedes_fact_id,)),
                ],
            )
            for e in sorted(
                report.source.executions, key=lambda e: (e.sequence, e.execution_id, e.revision)
            )[offset : offset + limit]
        ]
    else:
        total = len(report.source.journal_entries)
        rows = [
            PersonalJournalRow(
                kind="journal",
                entry_id=e.entry_id,
                sequence=index,
                occurred_at=e.effective_at,
                event_type=e.kind.value,
                description="Canonical journal tuple index; reference " + e.reference_id,
                amounts=[
                    PersonalNamedValue(
                        name=f"{p.account}:{p.currency}:{p.instrument_id or ''}:{name}",
                        value=_plain(getattr(p, name)),
                    )
                    for p in e.postings
                    for name in ("debit", "credit", "units_delta")
                ],
                source_row_ids=[e.reference_id],
            )
            for index, e in enumerate(
                report.source.journal_entries[offset : offset + limit], start=offset
            )
        ]
    return PersonalRunRows(
        job_id=job.job_id,
        report_sha256=report_sha256,
        kind=kind,
        offset=offset,
        limit=limit,
        total=total,
        rows=rows,
    )


def comparison_view(
    items: tuple[tuple[ResearchRunRequest, ResearchJobView, ReportArtifact, str], ...],
) -> PersonalComparison:
    _require(
        type(items) is tuple and 2 <= len(items) <= 8,
        "comparison requires two to eight retained runs",
    )
    _require(
        len({job.job_id for _, job, _, _ in items}) == len(items), "comparison jobs must be unique"
    )
    views = []
    bases = []
    differences = []
    for request, job, artifact, cost in items:
        report = _published(job, artifact, request)
        _cost(request, cost)
        spec = request.spec
        bases.append(
            {
                "dataset": (spec.dataset_id, spec.dataset_sha256, spec.data_class),
                "instruments": spec.instruments,
                "events": spec.events_sha256,
                "calendar": spec.calendar,
                "warmup": report.interval.warmup_sessions,
                "scoring": report.interval.expected_sessions,
                "reset": report.interval.reset_mode,
                "initial_cash": spec.initial_cash,
                "availability": spec.availability_mode,
                "price_basis": spec.feature_price_basis,
                "revision_policy": spec.revision_policy,
                "valuation_conventions": report.conventions,
                "implementation": tuple(
                    p for p in spec.pins if not p.name.startswith("evaluation_")
                ),
                "execution_model": replace(
                    spec.execution_policy, slippage_bps=Decimal(5), fee_per_share=Decimal(".01")
                ),
                "risk_policy": replace(spec.risk_policy, fee_per_share=Decimal(".01")),
                "financing": (
                    spec.financing_policy,
                    spec.eligibility_policy,
                    spec.account_privileges,
                ),
                "flows": tuple(
                    (
                        f.flow.kind,
                        f.signed_amount,
                        f.flow.effective_at,
                        f.flow.recorded_at,
                        f.origin,
                    )
                    for f in report.source.flows
                ),
            }
        )
        differences.extend(
            [
                PersonalNamedValue(
                    name=job.job_id + ":configuration",
                    value=_plain(configuration_view(spec.strategy_configuration).model_dump_json()),
                ),
                PersonalNamedValue(name=job.job_id + ":cost_scenario", value=cost),
            ]
        )
        views.append(
            PersonalComparisonItem(
                job_id=job.job_id,
                run_id=job.run_id,
                report_sha256=report.semantic_sha256,
                dataset_id=spec.dataset_id,
                data_class=spec.data_class.value,
                strategy_id=spec.strategy_configuration.kind,
                configuration=configuration_view(spec.strategy_configuration),
                cost_scenario_id=cost,
                interval=_interval(report.interval),
                metrics=[_metric(m) for m in report.metrics],
                benchmark_metrics=[_metric(m) for m in report.benchmark.metrics],
                assumptions=_assumptions(report),
                limitations=list(report.limitations),
            )
        )
    reasons = [
        "comparison_basis_differs:" + key
        for key, value in bases[0].items()
        if any(b[key] != value for b in bases[1:])
    ]
    if any(a.report.status != "completed" for _, _, a, _ in items):
        reasons.append("incomplete_report")
    return PersonalComparison(
        comparison_sha256=content_digest(
            tuple((r.spec.semantic_sha256, j.job_id, a.semantic_sha256, c) for r, j, a, c in items)
        ),
        comparable=not reasons,
        reasons=reasons,
        differences=differences,
        runs=views,
    )
