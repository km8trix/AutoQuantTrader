"""Build immutable reports from the one engine's accepted output, without I/O."""

from __future__ import annotations

from datetime import datetime
from decimal import localcontext

from packages.domain.metrics import (
    ReportInputError,
    derive_benchmark,
    derive_metrics,
    derive_return_path,
    scored_valuations,
)
from packages.domain.personal_contracts import require_text, require_utc
from packages.domain.report_contracts import (
    EngineResult,
    ReportArtifact,
    ReportConventions,
    RunReport,
)
from packages.domain.wealth import derived_context


def build_run_report(result: EngineResult, conventions: ReportConventions) -> RunReport:
    """Preserve accepted source facts and derive a semantic economic report."""
    if type(result) is not EngineResult or type(conventions) is not ReportConventions:
        raise ReportInputError("report requires exact engine output and conventions")
    pins = {pin.name: pin for pin in result.spec.pins}
    exact = pins.get("report_conventions")
    if exact is not None:
        if exact.sha256 != conventions.semantic_sha256:
            raise ReportInputError("report conventions differ from RunSpec")
    elif conventions != ReportConventions() or pins["report"].version != conventions.version:
        raise ReportInputError("custom conventions require their exact RunSpec pin")
    if result.interval.fold_id != result.spec.evaluation.fold_id:
        raise ReportInputError("report fold differs from RunSpec")
    if result.interval.expected_sessions != result.spec.evaluation.scored_sessions:
        raise ReportInputError("report session coverage differs from RunSpec")
    if result.interval.warmup_sessions != result.spec.evaluation.warmup_sessions:
        raise ReportInputError("report warmup differs from RunSpec")
    if (
        result.final_snapshot.account_id != result.spec.account_id
        or result.final_state.account_id != result.spec.account_id
    ):
        raise ReportInputError("engine final state belongs to another account")
    rows = scored_valuations(result.valuations, result.interval)
    with localcontext(derived_context()):
        for row in result.valuations:
            snapshot = row.snapshot
            if snapshot.account_id != result.spec.account_id:
                raise ReportInputError("valuation belongs to another account")
            if snapshot.nav is None and not snapshot.valuation_reasons:
                raise ReportInputError("missing authoritative NAV requires source reasons")
            if snapshot.nav is not None and snapshot.market_value is not None:
                expected = (
                    snapshot.trade_date_cash + snapshot.market_value + snapshot.dividend_receivable
                )
                settled = (
                    snapshot.settled_cash
                    + snapshot.trade_receivable
                    - snapshot.trade_payable
                    + snapshot.market_value
                    + snapshot.dividend_receivable
                )
                if snapshot.nav != expected or snapshot.nav != settled:
                    raise ReportInputError("accepted NAV and cash classifications do not reconcile")
    returns = derive_return_path(
        valuations=result.valuations,
        flows=result.flows,
        interval=result.interval,
        conventions=conventions,
    )
    metrics = derive_metrics(
        valuations=result.valuations,
        flows=result.flows,
        executions=result.executions,
        fifo_matches=result.fifo_matches,
        returns=returns,
        interval=result.interval,
        conventions=conventions,
    )
    benchmark = derive_benchmark(
        inputs=result.benchmark_inputs,
        valuations=result.valuations,
        flows=result.flows,
        interval=result.interval,
        conventions=conventions,
    )
    reasons = set(result.reasons)
    complete = result.status == "completed"
    if not rows or rows[-1].row_id != result.interval.terminal_valuation_id:
        if complete:
            raise ReportInputError("completed result omits its baseline/terminal valuation")
        reasons.add("missing_terminal_valuation")
    if not complete:
        reasons.add("incomplete_attempt")
    limitations = set(result.spec.limitations)
    limitations.add("source-class:" + result.spec.data_class.value)
    limitations.add("availability:" + result.spec.availability_mode)
    if len(result.interval.expected_sessions) < conventions.minimum_annualized_sessions:
        limitations.add("insufficient_scored_sessions_for_annualization")
    return RunReport(
        result.run_id,
        result.semantic_sha256,
        conventions,
        "completed" if complete else "incomplete",
        result.interval,
        metrics,
        returns,
        benchmark,
        result,
        tuple(sorted(reasons)),
        tuple(sorted(limitations)),
    )


def build_report_artifact(
    report: RunReport, *, attempt_id: str, generated_at: datetime
) -> ReportArtifact:
    """Attach generation metadata without changing the semantic report identity."""
    if type(report) is not RunReport:
        raise ReportInputError("artifact requires an exact report")
    require_text(attempt_id, "report attempt")
    require_utc(generated_at, "report generation time")
    if any(row.snapshot.point.knowledge_at > generated_at for row in report.source.valuations):
        raise ReportInputError("artifact predates retained valuation knowledge")
    return ReportArtifact(report, attempt_id, generated_at)
