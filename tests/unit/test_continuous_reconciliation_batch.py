"""Source-scoped fixture facts run through the sole engine and real accounting."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest

from packages.application.causal_engine import (
    advance_continuous_engine_with_applications,
)
from packages.application.continuous_account_transition import ContinuousAccountTransitionPreparer
from packages.application.personal_codec import decode_record, encode_record
from packages.application.reference_strategy import ReferenceStrategy
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier
from packages.domain.continuous_reconciliation_contracts import ContinuousReconciliationBatch
from packages.domain.engine_contracts import EngineEvent, ObservationProvenance
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.personal_contracts import content_digest
from tests.unit.test_account_reconciliation import wrap
from tests.unit.test_continuous_engine import (
    FixtureEvidence,
    economic_values,
    inputs_and_prices,
    start,
)
from tests.unit.test_continuous_fact_results import RejectSelectedFlow


def flow(checkpoint, amount, name):
    at = checkpoint.now + timedelta(seconds=1)
    return create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION if amount > 0 else CashFlowKind.WITHDRAWAL,
        currency="USD",
        amount=Decimal(abs(amount)),
        effective_at=at,
        recorded_at=at,
        external_reference=name,
    )


def frontier(checkpoint, pairs, *, prior=(), name="observed-fixture", at=None):
    at = at or max(page.received_at for _, page in pairs) + timedelta(seconds=1)
    batch = ContinuousReconciliationBatch(
        scope=pairs[0][0].scope,
        facts=tuple(item for item, _ in pairs),
        source_receipts=tuple(page for _, page in pairs),
        prior_applications=prior,
        source_order=tuple(item.observation.fact_id for item, _ in pairs),
        source_closure_sha256=content_digest(tuple(pairs)),
    )
    event = EngineEvent(
        name,
        at,
        at,
        batch,
        ObservationProvenance(
            checkpoint.inputs.spec.data_class,
            "synthetic-observed-fact-closure/1",
            content_digest(batch),
            simulated_available_at=at,
            assumption_id="explicit-synthetic-fixture/1",
        ),
    )
    return ClosedEngineFrontier(
        frontier_id=name,
        stream_id=checkpoint.inputs.spec.run_id,
        previous_checkpoint_sha256=checkpoint.semantic_sha256,
        source_frontier_sha256=batch.source_closure_sha256,
        knowledge_at=at,
        events=(event,),
    )


def advance(checkpoint, boundary, *, accounting=None):
    return advance_continuous_engine_with_applications(
        checkpoint,
        boundary,
        expected_sha256=checkpoint.semantic_sha256,
        accounting=accounting or PersonalAccounting(),
        strategy=ReferenceStrategy(),
        runtime_evidence=FixtureEvidence(checkpoint.inputs.spec),
    )


def case():
    inputs, _ = inputs_and_prices()
    checkpoint = start(inputs)
    return checkpoint, SimpleNamespace(state=checkpoint.state)


def test_real_accounting_preserves_cash_order_wealth_and_original_duplicate_application_time():
    checkpoint, h = case()
    pairs = [
        wrap(h, flow(checkpoint, 500, "deposit")),
        wrap(h, flow(checkpoint, -10400, "withdraw")),
    ]
    boundary = frontier(checkpoint, pairs)
    result, batches = advance(checkpoint, boundary)
    applied = batches[0]
    assert result.current.snapshot.trade_date_cash == Decimal(100)
    assert not applied.reasons and not result.state.halted
    assert [row.signed_amount for row in result.flows[-2:]] == [Decimal(500), Decimal(-10400)]
    assert all(app.applied_at == boundary.knowledge_at for app in applied.applications)
    assert len(result.valuations) >= len(checkpoint.valuations) + 4
    restarted = decode_record(encode_record(checkpoint), type(checkpoint))
    replayed, replay_batches = advance(restarted, boundary)
    assert economic_values(replayed) == economic_values(result)
    assert replay_batches == batches
    duplicate = frontier(
        result,
        pairs,
        prior=applied.applications,
        name="overlap",
        at=result.now + timedelta(seconds=1),
    )
    repeated, new_batches = advance(result, duplicate)
    assert repeated.state == result.state
    assert new_batches[0].applications == applied.applications
    assert set(new_batches[0].duplicate_fact_ids) == {item.observation.fact_id for item, _ in pairs}
    assert advance(repeated, duplicate) == (repeated, ())


def test_rejected_fact_blocks_dependent_only_and_does_not_leave_partial_flow():
    checkpoint, h = case()
    bad = wrap(h, flow(checkpoint, 100, "rejected"))
    dependent = wrap(h, flow(checkpoint, 200, "dependent"), parents=(bad[0].observation.fact_id,))
    valid = wrap(h, flow(checkpoint, 7, "independent"))
    accounting = RejectSelectedFlow(bad[0].command.command_id)
    result, (applied,) = advance(
        checkpoint, frontier(checkpoint, [bad, dependent, valid]), accounting=accounting
    )
    assert result.current.snapshot.trade_date_cash == Decimal(10007)
    assert result.state.halted
    assert applied.unresolved_fact_ids == tuple(
        sorted((bad[0].observation.fact_id, dependent[0].observation.fact_id))
    )
    assert [app.fact_id for app in applied.applications] == [valid[0].observation.fact_id]
    assert len(result.flows) == len(checkpoint.flows) + 1
    assert len([v for v in result.valuations if "pre_flow" in v.roles]) == 2


def test_quarantined_source_and_external_cash_keep_blocker_but_observation_continues():
    checkpoint, h = case()
    invalid, page = wrap(h, flow(checkpoint, 500, "bad-receipt"))
    valid = wrap(h, flow(checkpoint, 7, "manual-cash"), origin="external")
    result, (applied,) = advance(
        checkpoint, frontier(checkpoint, [(replace(invalid, source_sha256="f" * 64), page), valid])
    )
    assert applied.quarantined_fact_ids == (invalid.observation.fact_id,)
    assert "EXTERNAL_ACTIVITY_REQUIRES_OWNER_DISPOSITION" in applied.reasons
    assert result.current.snapshot.trade_date_cash == Decimal(10007) and result.state.halted
    later = wrap(
        SimpleNamespace(state=result.state), flow(result, 3, "later-observed"), origin="external"
    )
    observed, _ = advance(result, frontier(result, [later], name="later-observation"))
    assert observed.current.snapshot.trade_date_cash == Decimal(10010) and observed.state.halted


def test_preparer_retains_actual_engine_application_results_in_its_owned_fingerprint():
    checkpoint, h = case()
    owner = ContinuousAccountTransitionPreparer(
        accounting=PersonalAccounting(),
        strategy=ReferenceStrategy(),
        runtime_evidence=FixtureEvidence(checkpoint.inputs.spec),
    )
    result = owner.prepare_frontier(
        command_id="cash-frontier",
        checkpoint=checkpoint,
        frontier=frontier(checkpoint, [wrap(h, flow(checkpoint, 7, "cash"))]),
    )
    owner.require_prepared(result)
    assert len(result.application_batches) == 1
    object.__setattr__(result, "application_batches", ())
    with pytest.raises(ValueError, match="OWNED"):
        owner.require_prepared(result)


def test_reconciliation_batch_is_explicitly_outside_finite_source_tapes():
    from packages.application.causal_engine import run_causal_engine
    from packages.application.personal_inputs import synthetic_engine_inputs
    from tests.unit.test_causal_checkpoint import PINS

    checkpoint, h = case()
    event = frontier(checkpoint, [wrap(h, flow(checkpoint, 7, "finite-forbidden"))]).events[0]
    inputs = synthetic_engine_inputs(fixture="flat", pins=PINS, session_count=8, warmup_count=2)
    events = tuple(sorted((*inputs.events, event), key=lambda item: item.event_id))
    inputs = replace(
        inputs, events=events, spec=replace(inputs.spec, events_sha256=content_digest(events))
    )
    result = run_causal_engine(
        inputs, accounting=PersonalAccounting(), strategy=ReferenceStrategy()
    )
    assert result.status == "rejected"
    assert result.reasons == ("CONTINUOUS_RECONCILIATION_NOT_A_FINITE_SOURCE",)


@pytest.mark.parametrize("change", ["account", "time"])
def test_initial_application_cannot_be_reconstructed_from_amount_or_refreshed_time(change):
    from packages.application.continuous_venue_frontier import continuous_initial_cash_application

    checkpoint, _ = case()
    if change == "account":
        checkpoint = replace(
            checkpoint,
            inputs=replace(
                checkpoint.inputs,
                spec=replace(checkpoint.inputs.spec, account_binding_sha256="b" * 64),
            ),
        )
    else:
        identity = checkpoint.state.cash_flows[0].cash_flow_id
        checkpoint = replace(
            checkpoint,
            trace=tuple(
                replace(
                    row,
                    point=replace(
                        row.point, knowledge_at=row.point.knowledge_at + timedelta(seconds=1)
                    ),
                )
                if row.event_id == identity
                else row
                for row in checkpoint.trace
            ),
        )
    with pytest.raises(ValueError, match="initial capital"):
        continuous_initial_cash_application(checkpoint, accounting=PersonalAccounting())
