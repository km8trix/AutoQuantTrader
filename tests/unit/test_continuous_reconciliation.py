"""Actual engine checkpoints; references are synthetic and confer no SQL authority."""

from dataclasses import replace
from datetime import timedelta
from hashlib import sha256

import pytest

from packages.application.continuous_reconciliation import (
    ContinuousReconciliationTransitionResolver,
)
from packages.application.personal_codec import encode_record
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.continuous_account_contracts import CanonicalAccountTransitionRef
from packages.domain.personal_contracts import content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.research_job_contracts import ObjectRef
from tests.unit.test_continuous_engine import inputs_and_prices, start


def case():
    checkpoint = start(inputs_and_prices()[0])
    payload = encode_record(checkpoint)
    snapshot = checkpoint.current.snapshot
    heads = ReconciliationHeads(
        snapshot.journal_sha256,
        snapshot.order_sha256,
        content_digest(()),
        0,
        content_digest(()),
        0,
        1,
    )
    reference = CanonicalAccountTransitionRef(
        account_id=checkpoint.state.account_id,
        account_binding_sha256=checkpoint.inputs.spec.account_binding_sha256,
        command_id="retained-initialization",
        command_sha256=content_digest(checkpoint.inputs),
        previous_checkpoint_sha256=None,
        checkpoint=ObjectRef(sha256(payload).hexdigest(), len(payload)),
        checkpoint_sha256=checkpoint.semantic_sha256,
        expected_heads=heads,
        resulting_heads=heads,
        source_closure_sha256=content_digest(checkpoint.inputs.bootstrap_events),
        applied_at=checkpoint.now,
    )
    return checkpoint, reference


def test_recomparison_uses_canonical_state_and_distinct_fact_stage_without_mutation():
    checkpoint, reference = case()
    before = encode_record(checkpoint)
    result = ContinuousReconciliationTransitionResolver(
        accounting=PersonalAccounting()
    ).resolve_transition(reference, checkpoint)
    assert result.current.state == checkpoint.state
    assert result.current.snapshot.trade_date_cash == checkpoint.current.snapshot.trade_date_cash
    assert result.context.point.stage == 1
    assert result.current.snapshot.point == result.context.point
    assert result.current.snapshot.journal_sha256 == checkpoint.current.snapshot.journal_sha256
    assert result.current.snapshot.order_sha256 == checkpoint.current.snapshot.order_sha256
    assert result.context.approved_snapshot is None and result.context.risk_policy_sha256 is None
    assert encode_record(checkpoint) == before


@pytest.mark.parametrize(
    "field",
    ["account_id", "account_binding_sha256", "checkpoint_sha256", "applied_at", "ledger", "order"],
)
def test_exact_retained_scope_time_and_projection_heads_are_required(field):
    checkpoint, reference = case()
    if field == "account_id":
        reference = replace(reference, account_id="another-account")
    elif field == "applied_at":
        reference = replace(reference, applied_at=reference.applied_at + timedelta(seconds=1))
    elif field in ("ledger", "order"):
        reference = replace(
            reference,
            resulting_heads=replace(reference.resulting_heads, **{field + "_sha256": "f" * 64}),
        )
    else:
        reference = replace(reference, **{field: "f" * 64})
    with pytest.raises(ValueError):
        ContinuousReconciliationTransitionResolver(
            accounting=PersonalAccounting()
        ).resolve_transition(reference, checkpoint)
