"""B-owned historical queries; fixtures grant no original C or signed-owner authority."""

from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa

from packages.persistence.daily_runtime_risk import DailyRuntimeRiskConflict
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignments
from tests.integration.test_sql_daily_runtime_risk import (
    _write_transaction,
    harness,
)

__all__ = ["harness"]


def test_original_assignment_prefix_allows_later_assignment_and_control(harness):
    first = harness.resolved()
    view = harness.store.inspect_assignment_prefix(
        first, assignment_generation=1, through_coordinator_sequence=0, commitment_ids=()
    )
    assert view.before_assignment is None
    assert view.after_assignment == first.assignment
    assert view.command.after_assignment_sha256 == first.assignment.semantic_sha256
    assert view.control == first.control
    assert view.obligations.bindings == view.attempts == view.attempt_envelopes == ()
    harness.enable()
    assert harness.resolved().assignment.generation == 2
    harness.store.require_assignment_prefix(view)
    with _write_transaction(harness.engine) as connection:
        harness.store.recheck_assignment_prefix_in_transaction(connection, view)


def test_nonempty_assignment_prefix_keeps_actual_admission_and_hold_lineage(harness):
    harness.enable()
    harness.admit(harness.request())
    current = harness.resolved()
    ids = tuple(binding.commitment.commitment_id for binding in current.obligations.bindings)
    view = harness.store.inspect_assignment_prefix(
        current, assignment_generation=2, through_coordinator_sequence=0, commitment_ids=ids
    )
    assert view.obligations == current.obligations
    assert view.before_assignment == current.assignment_rows[0]
    with _write_transaction(harness.engine) as connection:
        harness.store.recheck_assignment_prefix_in_transaction(connection, view)
    # Cutoff and IDs are query selections. The actual C reader must independently
    # authenticate them against the original checkpoint before accepting association.
    with pytest.raises(DailyRuntimeRiskConflict, match="missing from retained"):
        harness.store.inspect_assignment_prefix(
            current,
            assignment_generation=2,
            through_coordinator_sequence=0,
            commitment_ids=("not-a-retained-hold",),
        )


@pytest.mark.parametrize("change", ["clone", "deadline", "hold_ids"])
def test_assignment_prefix_rejects_replaced_or_mutated_owned_values(harness, change):
    view = harness.store.inspect_assignment_prefix(
        harness.resolved(),
        assignment_generation=1,
        through_coordinator_sequence=0,
        commitment_ids=(),
    )
    if change == "clone":
        view = replace(view)
    elif change == "deadline":
        object.__setattr__(view.command, "expires_at", view.command.expires_at + timedelta(days=1))
    else:
        object.__setattr__(view, "commitment_ids", ("invented",))
    with pytest.raises(DailyRuntimeRiskConflict):
        harness.store.require_assignment_prefix(view)
    with _write_transaction(harness.engine) as connection, pytest.raises(DailyRuntimeRiskConflict):
        harness.store.recheck_assignment_prefix_in_transaction(connection, view)


def test_assignment_prefix_recheck_rejects_changed_original_after_later_head(harness):
    view = harness.store.inspect_assignment_prefix(
        harness.resolved(),
        assignment_generation=1,
        through_coordinator_sequence=0,
        commitment_ids=(),
    )
    harness.enable()
    with harness.engine.begin() as connection:
        connection.execute(
            sa.update(daily_runtime_assignments)
            .where(
                daily_runtime_assignments.c.account_id == harness.account,
                daily_runtime_assignments.c.generation == 1,
            )
            .values(command_sha256="a" * 64)
        )
    with _write_transaction(harness.engine) as connection, pytest.raises(DailyRuntimeRiskConflict):
        harness.store.recheck_assignment_prefix_in_transaction(connection, view)


@pytest.mark.parametrize("nested", [False, True])
def test_assignment_prepared_original_guard_detects_in_place_mutation(harness, nested):
    prepared = harness.prepare_assignment(harness.assignment, harness.last_owner_receipt)
    harness.store.require_prepared_assignment(prepared)
    if nested:
        object.__setattr__(prepared.result.policy, "max_symbol_nav_fraction", "0")
    else:
        object.__setattr__(prepared, "valid_until", prepared.valid_until + timedelta(days=1))
    with pytest.raises((DailyRuntimeRiskConflict, TypeError, ValueError)):
        harness.store.require_prepared_assignment(prepared)
    with _write_transaction(harness.engine) as connection, pytest.raises(DailyRuntimeRiskConflict):
        harness.store.require_prepared_assignment_in_transaction(connection, prepared)


def test_assignment_poststate_requires_actual_owner_source_callback(harness):
    prepared = harness.prepare_assignment(harness.assignment, harness.last_owner_receipt)
    harness.store.require_prepared_assignment(prepared)
    with (
        _write_transaction(harness.engine) as connection,
        pytest.raises(DailyRuntimeRiskConflict, match="actual owner source"),
    ):
        harness.store.recheck_installed_assignment_in_transaction(
            connection, prepared, fence=harness.lease.fence
        )
