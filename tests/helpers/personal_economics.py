"""Financial integration oracles driven by explicit test commands, never an engine.

This helper does not call run_causal_engine, a strategy or a provider. It reuses
the unit test's explicit command driver and wraps actual PersonalAccounting
outputs in visibly labelled synthetic report inputs. No daily-close or annualized
coverage is claimed for these few intraday economic checkpoints.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, time
from decimal import Decimal
from zoneinfo import ZoneInfo

from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingState,
    Commitment,
    InstallCommitment,
)
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import (
    DailyRiskPolicy,
    DailyStrategyState,
    EngineTraceRow,
    EvaluationSpec,
    RunSpec,
)
from packages.domain.models import Side
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.report_contracts import (
    EngineResult,
    ExternalFlowRow,
    ReportConventions,
    ScoredInterval,
    ValuationRow,
)
from packages.domain.research_dataset import ResearchCalendar, ResearchDataClass, ResearchSession
from tests.unit.test_personal_accounting import BASE, POLICY, Harness

LABEL = "synthetic-financial-oracle-command-driver-not-application-engine/1"
ET = ZoneInfo("America/New_York")


class OracleDriver(Harness):
    """Every financial command and valuation instant is chosen by the test."""

    def __init__(
        self,
        *,
        base=BASE,
        policy=POLICY,
        account_id="synthetic-account",
        instruments=(("spy", "SPY"),),
        limitations=(),
    ):
        self.risk_policy = DailyRiskPolicy(
            policy_id="explicit-financial-oracle/1",
            policy_scope="synthetic_oracle",
            max_order_nav_fraction=Decimal(1),
            max_batch_nav_fraction=Decimal(1),
            max_symbol_nav_fraction=Decimal(1),
            max_gross_nav_fraction=Decimal(1),
        )
        self.instruments = instruments
        self.limitations = limitations
        self.commands = []
        self.trace = []
        super().__init__(policy=policy, base=base, funding=None)
        self.state = AccountingState(account_id)
        self.initial_state = self.state
        self.initial = self.project()
        self.funding = None
        self.baseline = None

    def context(self, **kwargs):
        context = super().context(**kwargs)
        return replace(
            context,
            run_id=LABEL,
            instruments=self.instruments,
            risk_policy_sha256=self.risk_policy.semantic_sha256
            if context.approved_snapshot is not None
            else None,
        )

    def apply(self, payload, **kwargs):
        # Test-chosen approvals bind this oracle policy. No risk/strategy engine
        # is run, and canonical broker/accounting source facts stay unchanged.
        if isinstance(payload, InstallCommitment):
            payload = replace(
                payload,
                commitment=replace(
                    payload.commitment, policy_sha256=self.risk_policy.semantic_sha256
                ),
            )
        before = self.project()
        result = super().apply(payload, **kwargs)
        command = AccountingCommand(kwargs.get("command_id") or f"command-{self.sequence}", payload)
        self.commands.append(command)
        self.trace.append(
            EngineTraceRow(
                event_id=f"oracle-command-{self.sequence}",
                point=result.snapshot.point,
                kind=f"oracle:{type(payload).__name__}:{result.disposition}",
                causal_input_sha256=command.semantic_sha256,
                prior_snapshot_sha256=before.snapshot.semantic_sha256,
                next_snapshot_sha256=result.snapshot.semantic_sha256,
                state_sha256=result.state.semantic_sha256,
                reasons=result.reasons,
                causal_content_sha256=command.semantic_sha256,
            )
        )
        return result

    def fund(self, fact):
        assert self.funding is None and not self.commands
        result = self.apply(fact, at=fact.recorded_at)
        assert result.disposition == "applied", result.reasons
        self.funding = fact
        self.baseline = result
        return result

    def install_exact_submission(self, submission, *, approved_price, fee_budget):
        """Install a preserved canonical order under an explicit permissive oracle cap.

        Its original ACCEPTED/execution facts are applied separately; this helper
        does not generate replacement acceptances or use any modeled fills.
        """
        source = self.project().snapshot
        intent = submission.intent
        quantity = intent.quantity
        cash = quantity * approved_price + fee_budget if intent.side is Side.BUY else fee_budget
        commitment = Commitment(
            commitment_id="oracle-commitment:" + submission.order_id,
            intent_id=intent.intent_id,
            order_id=submission.order_id,
            instrument_id=intent.instrument_id,
            symbol=intent.symbol,
            side=intent.side,
            original_quantity=quantity,
            filled_quantity=Decimal(0),
            remaining_quantity=quantity,
            reserved_cash=cash,
            reserved_sell_quantity=quantity if intent.side is Side.SELL else Decimal(0),
            approved_price=approved_price,
            remaining_fee_budget=fee_budget,
            source_session=submission.submitted_at.astimezone(ET).date(),
            execution_session=submission.submitted_at.astimezone(ET).date(),
            created_sequence=self.sequence,
            not_before=submission.submitted_at,
            expires_at=intent.expires_at,
            policy_sha256=self.risk_policy.semantic_sha256,
            snapshot_sha256=source.semantic_sha256,
        )
        result = self.apply(
            InstallCommitment(submission, commitment),
            at=submission.submitted_at,
            approved=source,
        )
        assert result.disposition == "applied", result.reasons
        return commitment

    def result(self, case_id, *, limitations=()):
        assert self.funding is not None and self.baseline is not None
        final = self.project()
        interval_id = f"oracle-interval:{case_id}"
        baseline_id, terminal_id = f"{case_id}:funded-baseline", f"{case_id}:terminal"
        initial_id = f"{case_id}:before-initial-funding"
        first_day = self.funding.effective_at.astimezone(ET).date()
        last_day = self.at.astimezone(ET).date()
        days = tuple(sorted({first_day, last_day}))
        calendar = ResearchCalendar(
            f"oracle-checkpoint-calendar:{case_id}",
            "1",
            "XNYS",
            "America/New_York",
            tuple(
                ResearchSession(
                    "XNYS",
                    day,
                    datetime.combine(day, time(9, 30), ET).astimezone(UTC),
                    datetime.combine(day, time(16), ET).astimezone(UTC),
                    "regular",
                )
                for day in days
            ),
        )
        initial = ValuationRow(
            initial_id,
            self.initial.snapshot,
            self.funding.effective_at,
            first_day,
            ("pre_flow",),
            False,
            interval_id,
            self.funding.cash_flow_id,
            baseline_id,
        )
        baseline = ValuationRow(
            baseline_id,
            self.baseline.snapshot,
            self.funding.effective_at,
            first_day,
            ("post_flow", "baseline"),
            False,
            interval_id,
            self.funding.cash_flow_id,
            initial_id,
        )
        terminal = ValuationRow(
            terminal_id,
            final.snapshot,
            self.at,
            last_day,
            ("terminal",),
            True,
            interval_id,
        )
        limitations = tuple(
            sorted(
                {
                    LABEL,
                    "intraday-economic-checkpoints-not-daily-close-coverage",
                    *self.limitations,
                    *limitations,
                }
            )
        )
        pin_names = (
            "actions",
            "availability",
            "benchmark",
            "dependency_lock",
            "dirty_patch",
            "engine",
            "numeric",
            "report",
            "report_conventions",
            "source",
            "tzdata",
        )
        spec = RunSpec(
            account_id=self.state.account_id,
            dataset_id=f"oracle:{case_id}",
            dataset_sha256=content_digest((LABEL, case_id, tuple(self.commands))),
            events_sha256=content_digest(tuple(self.commands)),
            data_class=ResearchDataClass.SYNTHETIC_FIXTURE,
            availability_mode="modeled",
            instruments=self.instruments,
            calendar=calendar,
            strategy=VersionPin("strategy", "unused-in-command-driver/1", content_digest(LABEL)),
            strategy_configuration=ReferenceConfiguration(),
            evaluation=EvaluationSpec(case_id, (), days, LABEL),
            execution_policy=self.policy,
            risk_policy=self.risk_policy,
            pins=tuple(
                VersionPin(name, ReportConventions().version, ReportConventions().semantic_sha256)
                if name in {"report", "report_conventions"}
                else VersionPin(name, LABEL, content_digest((LABEL, name)))
                for name in pin_names
            ),
            initial_state_sha256=self.initial_state.semantic_sha256,
            initial_cash=self.funding.amount,
            limitations=limitations,
        )
        rejected = tuple(
            reason for row in self.trace if row.kind.endswith(":rejected") for reason in row.reasons
        )
        return EngineResult(
            spec=spec,
            status="rejected" if rejected else "completed",
            trace=tuple(self.trace),
            final_state=self.state,
            final_snapshot=final.snapshot,
            final_strategy_state=DailyStrategyState(values=(("driver", LABEL),)),
            valuations=(initial, baseline, terminal),
            flows=(
                ExternalFlowRow(
                    self.funding,
                    self.funding.amount,
                    self.baseline.snapshot.point.reduction_sequence,
                    initial_id,
                    baseline_id,
                    "initial_capital",
                    self.baseline.snapshot.journal_sha256,
                ),
            ),
            executions=final.executions,
            fifo_matches=final.fifo_matches,
            journal_entries=final.journal_entries,
            benchmark_inputs=(),
            interval=ScoredInterval(
                interval_id,
                case_id,
                baseline_id,
                terminal_id,
                days,
                (),
                content_digest(calendar),
            ),
            reasons=rejected,
        )
