from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import Inexact, localcontext

import pytest

from packages.application.daily_commitment_install import prepare_daily_commitments
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingState,
    AccountingTransition,
    ExecutionPolicy,
    InstallCommitment,
    SettlementCalendar,
)
from packages.domain.daily_risk import evaluate_daily_risk
from packages.domain.engine_contracts import DailyRiskPolicy
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.models import PositionTarget
from packages.domain.personal_contracts import CausalMark, ReductionPoint
from packages.domain.portfolio import daily_target_to_intents
from tests.unit.test_daily_risk import evidence
from tests.unit.test_daily_target_conversion import NOW, PIN, SHA, SOURCE, D, target


def install_case(*, two: bool = False) -> dict:
    port = PersonalAccounting()
    policy = ExecutionPolicy(
        SettlementCalendar("fixture", "1", tuple(date(2025, 2, d) for d in (3, 4, 5, 6, 7))),
        fee_per_share=D(".01"),
    )
    state = AccountingState("account")
    instruments = (("qqq", "QQQ"), ("spy", "SPY")) if two else (("spy", "SPY"),)
    context = AccountingContext(
        "fixture-run", ReductionPoint(1, 1, NOW, 2), NOW, "funding", SOURCE, instruments
    )
    funding = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=D(10000),
        effective_at=NOW,
        recorded_at=NOW,
        external_reference="explicit-synthetic-funding",
    )
    state = port.advance(
        state=state, command=AccountingCommand("funding", funding), context=context, policy=policy
    ).state
    for number, (instrument, symbol) in enumerate(instruments, 2):
        context = replace(
            context, event_id=instrument, point=replace(context.point, reduction_sequence=number)
        )
        mark = CausalMark(
            "mark-" + instrument,
            instrument,
            symbol,
            D(100),
            SOURCE,
            datetime(2025, 2, 3, 21, tzinfo=UTC),
            NOW,
            SHA,
        )
        state = port.advance(
            state=state,
            command=AccountingCommand("mark-" + instrument, mark),
            context=context,
            policy=policy,
        ).state
    context = replace(
        context,
        point=replace(
            context.point, reduction_sequence=context.point.reduction_sequence + 1, stage=5
        ),
    )
    snapshot = port.project(state=state, context=context, policy=policy).snapshot
    desired = replace(
        target("10"), targets=tuple(PositionTarget(i, s, D(10)) for i, s in instruments)
    )
    batch = daily_target_to_intents(desired, snapshot, strategy_pin=PIN)
    risk = DailyRiskPolicy()
    decision = evaluate_daily_risk(risk, snapshot, batch, evidence(snapshot.semantic_sha256), NOW)
    assert decision.approved, decision.reasons
    return dict(
        state=state,
        snapshot=snapshot,
        batch=batch,
        decision=decision,
        context=context,
        execution_policy=policy,
        risk_policy=risk,
        accounting=port,
    )


class Recorder(PersonalAccounting):
    def __init__(self, reject_at: int | None = None, exception: bool = False):
        self.calls = []
        self.reject_at = reject_at
        self.exception = exception

    def advance(self, *, state, command, context, policy) -> AccountingTransition:
        self.calls.append((command, context))
        if len(self.calls) == self.reject_at:
            if self.exception:
                raise ValueError("fixture failure")
            return replace(
                self.project(state=state, context=context, policy=policy),
                disposition="rejected",
                reasons=("FIXTURE_SECOND_INSTALL",),
            )
        return super().advance(state=state, command=command, context=context, policy=policy)


def test_actual_accounting_install_preserves_literal_engine_ids_and_sequence_context() -> None:
    case = install_case(two=True)
    recorder = Recorder()
    result = prepare_daily_commitments(**{**case, "accounting": recorder})
    assert result.disposition == "installed"
    assert len(result.transitions) == len(result.commitments) == 2
    assert result.last_reduction_sequence == case["context"].point.reduction_sequence + 2
    assert case["state"].commitments == ()
    assert result.state.commitments == result.commitments
    for index, (commitment, (command, context), intent) in enumerate(
        zip(result.commitments, recorder.calls, case["batch"].intents, strict=True), 1
    ):
        assert commitment.commitment_id == canonical_id("commitment", intent.intent_id)
        assert isinstance(command.payload, InstallCommitment)
        assert command.payload.submission.submission_attempt_id == canonical_id(
            "model-attempt", intent.intent_id
        )
        assert commitment.created_sequence == case["context"].point.reduction_sequence + index
        assert (
            context.point.stage == 6
            and context.point.reduction_sequence == commitment.created_sequence
        )
        assert context.approved_snapshot == case["snapshot"]
        assert context.risk_policy_sha256 == case["risk_policy"].semantic_sha256
        assert commitment.snapshot_sha256 == case["snapshot"].semantic_sha256
        assert commitment.reserved_cash == D("1010.10")
        assert commitment.approved_price == D(101) and commitment.remaining_fee_budget == D(".10")
    assert result.transitions[-1].snapshot.available_cash == D("7979.80")


@pytest.mark.parametrize("exception", [False, True])
def test_second_install_failure_keeps_only_original_state_and_consumed_sequence(
    exception: bool,
) -> None:
    case = install_case(two=True)
    recorder = Recorder(reject_at=2, exception=exception)
    result = prepare_daily_commitments(**{**case, "accounting": recorder})
    assert result.disposition == "rolled_back" and result.state is case["state"]
    assert result.transitions == result.commitments == ()
    assert result.last_reduction_sequence == case["context"].point.reduction_sequence + 2
    assert result.reasons == (
        ("INSTALL_EXCEPTION:ValueError",) if exception else ("FIXTURE_SECOND_INSTALL",)
    )


def test_attempt_namespace_is_explicit_and_does_not_change_cash_or_commitment_identity() -> None:
    case = install_case()
    old = prepare_daily_commitments(**case)
    new = prepare_daily_commitments(**case, attempt_namespace="daily-runtime-attempt")
    assert old.disposition == new.disposition == "installed"
    assert old.commitments[0].commitment_id == new.commitments[0].commitment_id
    assert old.commitments[0].reserved_cash == new.commitments[0].reserved_cash
    assert (
        old.state.submissions[0].submission_attempt_id
        != new.state.submissions[0].submission_attempt_id
    )
    with pytest.raises(ValueError, match="namespace"):
        prepare_daily_commitments(**case, attempt_namespace="provider")


def test_empty_approved_batch_consumes_no_sequence_and_rejected_decision_is_not_installed() -> None:
    case = install_case()
    empty = replace(case["batch"], intents=())
    decision = replace(case["decision"], batch=empty, reserved_cash_by_intent=())
    result = prepare_daily_commitments(**{**case, "batch": empty, "decision": decision})
    assert result.disposition == "no_intents" and result.state is case["state"]
    assert result.last_reduction_sequence == case["context"].point.reduction_sequence
    with pytest.raises(ValueError, match="approved decision"):
        prepare_daily_commitments(**{**case, "decision": replace(case["decision"], approved=False)})


@pytest.mark.parametrize("field", ["policy_sha256", "batch"])
def test_foreign_policy_or_batch_decision_rejects_before_accounting(field: str) -> None:
    case = install_case()
    change = "b" * 64 if field == "policy_sha256" else replace(case["batch"], batch_id="foreign")
    recorder = Recorder()
    with pytest.raises(ValueError, match="bind exactly"):
        prepare_daily_commitments(
            **{
                **case,
                "decision": replace(case["decision"], **{field: change}),
                "accounting": recorder,
            }
        )
    assert recorder.calls == []


def test_prospective_installs_ignore_ambient_decimal_precision_and_traps() -> None:
    case = install_case(two=True)
    expected = prepare_daily_commitments(**case)
    with localcontext() as context:
        context.prec = 1
        context.traps[Inexact] = True
        actual = prepare_daily_commitments(**case)
    assert actual == expected
