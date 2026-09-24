"""B history restoration with actual accounting and explicitly fixture-labelled sources.

The enclosing C parents, source-reader approval, and dispatch marks use the
existing synthetic fixtures. This test does not qualify actual C/A providers,
connected dispatch, or account trading authority.
"""

from datetime import timedelta
from decimal import Decimal

import pytest
import sqlalchemy as sa

from packages.application.causal_engine import continuous_runtime_action_context
from packages.domain.continuous_runtime_action import ContinuousRuntimeAction
from packages.domain.daily_attempt import daily_fence_reference
from packages.domain.daily_observed_hold_contracts import daily_runtime_effect_watermark
from packages.domain.order_reducer import BrokerOrderEventKind
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.stateful_venue_contracts import VenueCorrect
from packages.domain.submission_attempt import SubmissionAttemptState
from packages.persistence.daily_runtime_risk import (
    DailyRuntimeRiskConflict,
    RuntimeAttemptAccountingSource,
    daily_attempt_inventory_sha256,
)
from packages.persistence.daily_runtime_risk_schema import daily_runtime_hold_events
from tests.integration.test_daily_observed_holds import ObservedCase, retain_unknown_attempt
from tests.integration.test_sql_daily_runtime_risk import (
    _write_transaction,
    commit_attempt,
    envelope_for,
    prepare_attempt,
    retain_attempt_source,
)
from tests.unit.test_daily_attempt import event_after


def unknown_after_partial(case):
    """Record the second real in-flight attempt's UNKNOWN after observed partial economics."""
    h = case.h
    current = h.resolved()
    attempt = next(
        item for item in current.attempts if item.state is SubmissionAttemptState.IN_FLIGHT
    )
    name = "fixture-second-unknown-after-partial"
    at = h.clock.instant
    context = continuous_runtime_action_context(
        case.checkpoint, command_id=name, activation=False, checked_at=at
    )
    fence = daily_fence_reference(h.coordinator.revalidate(h.lease.fence))
    snapshot = case.checkpoint.current.snapshot
    source = RuntimeAttemptAccountingSource(
        account_id=h.account,
        coordinator_command_id=name,
        coordinator_sequence=case.sequence + 1,
        state=case.checkpoint.state,
        context=context,
        execution_policy=case.checkpoint.inputs.spec.execution_policy,
        obligations=current.obligations,
        heads=ReconciliationHeads(
            snapshot.journal_sha256,
            snapshot.order_sha256,
            current.obligations.semantic_sha256,
            daily_runtime_effect_watermark(
                attempt_envelopes=current.attempt_envelopes, observed_groups=current.observed_groups
            ),
            daily_attempt_inventory_sha256(current.attempts),
            current.control.sequence_number,
            h.lease.fencing_generation,
        ),
        fence=fence,
        checked_at=at,
        valid_until=min(at + timedelta(seconds=1), fence.valid_until),
        accounting_command=None,
        source_references=(case.put("daily-admission-producer/1", current.admissions[0]),),
    )
    reference = retain_attempt_source(h, source)
    event = event_after(
        attempt, SubmissionAttemptState.UNKNOWN, at, reason="fixture-late-uncertain-delivery"
    )
    envelopes = (envelope_for(source, reference, event),)
    action = ContinuousRuntimeAction(
        action_id=name,
        stream_id=case.checkpoint.inputs.spec.run_id,
        previous_checkpoint_sha256=case.checkpoint.semantic_sha256,
        source_closure_sha256=source.semantic_sha256,
        checked_at=at,
        attempt_events=(event,),
    )
    checkpoint = case.base.owner.prepare_runtime_action(
        command_id=name, checkpoint=case.checkpoint, action=action
    ).checkpoint
    result = commit_attempt(h, source, prepare_attempt(h, envelopes))
    assert result.accounting_state == checkpoint.state
    case.checkpoint, case.sequence = checkpoint, source.coordinator_sequence
    return result, envelopes


def test_unknown_group_uses_original_revision_when_later_corrections_repeat_hold_value(
    tmp_path, monkeypatch
):
    case = ObservedCase(tmp_path, two=True)
    try:
        retain_unknown_attempt(case)
        case.fill("2")
        case.commit(case.prepare("fixture-partial-before-second-unknown"))
        execution = next(
            item
            for item in case.venue.read().state.accounting.broker_events
            if item.kind is BrokerOrderEventKind.EXECUTION
        )
        case.execute(
            VenueCorrect(
                execution.execution_id,
                Decimal("1"),
                execution.price,
                execution.fee,
                "fixture original quantity correction",
            )
        )
        corrected = case.commit(case.prepare("fixture-original-corrected-hold"))
        original, envelopes = unknown_after_partial(case)
        before = case.h.resolved()
        view = case.h.store.inspect_attempt_group(before, envelopes=envelopes)
        assert view.result == original
        assert original.obligations == corrected.after
        selected_before = next(
            item.snapshot.rows
            for item in view.selected
            if item.snapshot.table is daily_runtime_hold_events
        )
        instrument = case.model.instruments[0][0]
        binding = next(
            item
            for item in original.obligations.bindings
            if item.commitment.instrument_id == instrument
        )
        assert binding.commitment.state == "unknown"
        for quantity in ("2", "1"):
            case.execute(
                VenueCorrect(
                    execution.execution_id,
                    Decimal(quantity),
                    execution.price,
                    execution.fee,
                    "fixture observed quantity correction",
                )
            )
            case.commit(case.prepare("fixture-repeat-quantity-" + quantity))
        after = case.h.resolved()
        assert after.attempts == original.attempts
        assert after.obligations == original.obligations
        with case.h.engine.connect() as connection:
            recurring = tuple(
                connection.execute(
                    sa.select(daily_runtime_hold_events.c.revision)
                    .where(
                        daily_runtime_hold_events.c.account_id == case.h.account,
                        daily_runtime_hold_events.c.hold_id == binding.commitment.commitment_id,
                        daily_runtime_hold_events.c.semantic_sha256 == binding.semantic_sha256,
                    )
                    .order_by(daily_runtime_hold_events.c.revision)
                ).scalars()
            )
        assert len(recurring) == 2 and recurring[0] < recurring[1]

        def forbidden(*_args, **_kwargs):
            raise AssertionError(
                "historical inspection must reuse the owned complete B source graph"
            )

        with monkeypatch.context() as patch:
            patch.setattr(case.h.store, "resolve_snapshot", forbidden)
            patch.setattr(case.h.store, "_resolved_attempt_sources", forbidden)
            patch.setattr(case.h.store, "_resolved_observed_sources", forbidden)
            restored = case.h.store.inspect_attempt_group(after, envelopes=envelopes)
        assert restored.result == original
        selected_after = next(
            item.snapshot.rows
            for item in restored.selected
            if item.snapshot.table is daily_runtime_hold_events
        )
        assert selected_after == selected_before
        assert (
            max(
                row["revision"]
                for row in selected_after
                if row["hold_id"] == binding.commitment.commitment_id
            )
            == recurring[0]
        )
        case.h.store.require_attempt_group_view(view)
        case.h.store.require_attempt_group_view(restored)
        with _write_transaction(case.h.engine) as connection:
            case.h.store.recheck_attempt_group_in_transaction(connection, view)
            case.h.store.recheck_attempt_group_in_transaction(connection, restored)
        # The later equal value cannot conceal corruption of the original revision.
        with case.h.engine.begin() as connection:
            connection.execute(
                sa.update(daily_runtime_hold_events)
                .where(
                    daily_runtime_hold_events.c.account_id == case.h.account,
                    daily_runtime_hold_events.c.hold_id == binding.commitment.commitment_id,
                    daily_runtime_hold_events.c.revision == recurring[0],
                )
                .values(payload=b"{}")
            )
        with (
            _write_transaction(case.h.engine) as connection,
            pytest.raises(DailyRuntimeRiskConflict),
        ):
            case.h.store.recheck_attempt_group_in_transaction(connection, restored)
    finally:
        case.close()
