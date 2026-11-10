"""Pure quiescence classification; these fixtures confer no source/store authority."""

from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from packages.persistence.runtime_owner_dependencies import (
    RuntimeOwnerDependencyError,
    SqlRuntimeOwnerDependencies,
)
from tests.unit.test_continuous_engine import inputs_and_prices, start, step
from tests.unit.test_daily_attempt import pending_case


def test_real_canonical_unsent_hold_blocks_cutover_even_after_nominal_expiry():
    inputs, prices = inputs_and_prices()
    checkpoint, _ = step(start(inputs), (prices[0],))
    assert checkpoint.state.commitments
    checkpoint, _ = step(
        checkpoint, (), at=checkpoint.state.commitments[0].expires_at + timedelta(hours=8)
    )
    previous, daily = SimpleNamespace(checkpoint=checkpoint), SimpleNamespace(attempts=())
    with pytest.raises(RuntimeOwnerDependencyError, match="UNRESOLVED_CAPACITY"):
        SqlRuntimeOwnerDependencies.require_quiescent_state(
            previous.checkpoint.state, daily.attempts
        )


def test_real_order_reducer_finds_working_submission_without_a_capacity_row():
    inputs, prices = inputs_and_prices()
    checkpoint, _ = step(start(inputs), (prices[0],))
    # Inconsistent inventory is rejected earlier by the public source verifier;
    # this independently checks the order-history backstop against hidden holds.
    checkpoint = SimpleNamespace(state=replace(checkpoint.state, commitments=()))
    previous, daily = SimpleNamespace(checkpoint=checkpoint), SimpleNamespace(attempts=())
    with pytest.raises(RuntimeOwnerDependencyError, match="WORKING_ORDER"):
        SqlRuntimeOwnerDependencies.require_quiescent_state(
            previous.checkpoint.state, daily.attempts
        )


def test_real_pending_attempt_blocks_cutover_when_canonical_account_has_no_orders():
    pending, _, _ = pending_case()
    inputs, _ = inputs_and_prices()
    previous, daily = (
        SimpleNamespace(checkpoint=start(inputs)),
        SimpleNamespace(attempts=(pending,)),
    )
    with pytest.raises(RuntimeOwnerDependencyError, match="UNRESOLVED_CAPACITY_OR_SENDS"):
        SqlRuntimeOwnerDependencies.require_quiescent_state(
            previous.checkpoint.state, daily.attempts
        )
