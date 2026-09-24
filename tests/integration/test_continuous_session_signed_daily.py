"""Signed owner history survives a lease change without overriding HALTED.

Daily data and clock health are explicitly modeled repository fixtures. The
account history, owner requests, lease, risk and publications are actual stores.
"""

from datetime import timedelta

from packages.domain.operational_control import OperationalControlState
from packages.domain.research_dataset import modeled_daily_availability
from packages.domain.stateful_venue_contracts import VenueCommand, VenueRunDue
from packages.persistence.daily_runtime_risk import SqlDailyRuntimeRisk
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from tests.integration.test_continuous_session import canonical_accounting, session_for
from tests.integration.test_continuous_session_owner_startup import genuine_captured_selection
from tests.integration.test_runtime_owner_dependencies import attach


def test_signed_selection_survives_new_lease_and_daily_risk_preserves_halt(tmp_path, monkeypatch):
    canonical_accounting(monkeypatch)
    fixture, _prior, enabled, initial_receipt, enabled_receipt = genuine_captured_selection(
        tmp_path, monkeypatch
    )
    pair, _dependencies, previous_runtime, *_ = fixture
    case, h = pair.base, pair.base.h
    try:
        original = pair.account.restore(case.scope)
        original_control = h.resolved().control
        old_fence = h.lease.fence
        day = case.inputs.spec.window.scored_sessions[0]
        at = modeled_daily_availability(day) + timedelta(milliseconds=50)
        h.coordinator.release(old_fence)
        h.clock.instant = h.decision_at = at
        h.lease = h.coordinator.acquire("signed-history-next-session-owner")
        assert h.lease.fence != old_fence
        h.store = SqlDailyRuntimeRisk(
            case.engine,
            coordinator=h.coordinator,
            codec=previous_runtime.codec,
            producers=previous_runtime,
            accounting=previous_runtime.accounting,
        )
        owners, runtime, *_ = attach(pair)
        session = session_for(pair, runtime)
        restored = pair.account.restore(case.scope)
        assert restored.checkpoint == original.checkpoint
        current = h.resolved()
        assert current.assignment == enabled
        assert current.control == original_control
        assert current.control.effective_state is OperationalControlState.HALTED
        associations = SqlRuntimeOwnerAssociations(owner_dependencies=owners)
        for generation, receipt in ((1, initial_receipt), (2, enabled_receipt)):
            retained = associations.read(
                case.scope, current=current, assignment_generation=generation
            )
            associations.require_association(retained)
            assert retained.request.read.receipt == receipt

        # Retain new independent observation times for this session. Original
        # bootstrap comparisons keep their expired times and cannot be renewed.
        for index in range(2):
            h.clock.instant += timedelta(milliseconds=1)
            session.delivery.venue.execute(
                VenueCommand(
                    f"signed-daily-independent-tick-{index}", h.clock.instant, VenueRunDue()
                )
            )
            session.reconcile(
                operation_id=f"signed-daily-observation-{index}",
                capture_id=f"signed-daily-capture-{index}",
            )
        assert pair.restore().reconciliation.resolved.result.status == "converged"
        h.clock.instant += timedelta(milliseconds=1)
        captured = case.add_capture(day)
        closure = case.closure(
            "signed-owner-daily-source",
            h.clock.instant,
            tuple(item.observation_id for item in captured.record.observations),
        )
        market = runtime.forward_sources.resolve(closure)
        sampler = runtime.operating.clock_sampler
        prepared_clock = runtime.operating.prepare_clock_append(
            sampler.sample(),
            expected_head=runtime.operating.journal.read_head(runtime.operating.clock_key()),
        )
        with pair.account.write_transaction() as connection:
            clock_reference = runtime.operating.append_clock_in_transaction(
                connection, prepared_clock
            )
        receipt = session.publish_daily(
            operation_id="signed-owner-halted-daily",
            market=market,
            clock_reference=clock_reference,
        )
        advanced = pair.account.restore(case.scope)
        assert advanced.receipt == receipt
        (decision,) = advanced.checkpoint.runtime_decisions[
            len(original.checkpoint.runtime_decisions) :
        ]
        assert not decision.decision.approved
        assert any(
            "HALTED" in reason or "CONTROL" in reason for reason in decision.decision.reasons
        )
        assert not decision.installed_commitments
        current = h.resolved()
        assert current.assignment == enabled and current.control == original_control
        assert not current.obligations.bindings and not current.attempts
        (admission,) = h.store.inspect_snapshot_admissions(current)
        assert admission.admission.decision == decision.decision

        # New exposure remains denied while an independent observation can
        # still advance the applied account and retain the original halt.
        h.clock.instant += timedelta(milliseconds=10)
        applied = session.reconcile(
            operation_id="signed-owner-halted-observation",
            capture_id="signed-owner-halted-capture",
        )
        observed = pair.account.restore(case.scope)
        assert observed.receipt == applied.continuous
        assert observed.checkpoint.state.cash_flows == original.checkpoint.state.cash_flows
        assert h.resolved().control == original_control
        assert not h.resolved().attempts
    finally:
        pair.close()
