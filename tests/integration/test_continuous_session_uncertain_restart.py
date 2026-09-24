"""Simulated post-commit interruption and in-process owner reconstruction.

The existing activation fixture labels initial assignment, operational re-arm,
market data and clocks as modeled. Actual independent venue commit and C/B/A
history are retained. This is not an OS process-crash or provider qualification.
"""

from datetime import timedelta
from time import perf_counter

import pytest

from packages.domain.stateful_venue_contracts import VenueAccept, VenueCommand, VenueSubmit
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.daily_runtime_risk import SqlDailyRuntimeRisk
from tests.integration import test_continuous_runtime_attempt_sources as attempt_fixture
from tests.integration.test_continuous_runtime_sources import fresh_reader
from tests.integration.test_continuous_session import canonical_accounting, session_for


def test_post_venue_commit_interruption_recovers_under_new_lease_without_resend(
    tmp_path, monkeypatch
):
    measured_at = perf_counter()

    def mark(label):
        nonlocal measured_at
        finished = perf_counter()
        print(f"uncertain restart {label}: {finished - measured_at:.3f}s", flush=True)
        measured_at = finished

    canonical_accounting(monkeypatch)
    fixture = attempt_fixture.attempt_case.__wrapped__(tmp_path, monkeypatch)
    try:
        initial = next(fixture)
        case, runtime, reader, _previous, current, _admission, _source, descriptor = (
            attempt_fixture.activation_preparation(initial)
        )
        pair = case.paired_fixture
        session = session_for(pair, runtime, reader)
        ids = tuple(sorted(item.attempt_id for item in current.attempts))
        assert len(ids) == 1
        clock_reference = descriptor.plan.operating.clock_reference
        quote_clock_reference = descriptor.plan.quote_clock.reference
        original_clock_bytes = runtime.codec.encode_record(clock_reference)
        original_quote_clock_bytes = runtime.codec.encode_record(quote_clock_reference)
        execute = session.delivery.venue.execute
        registered_receipts = []
        interruption = KeyboardInterrupt("explicit simulated interruption after venue COMMIT")

        def committed_then_interrupted(command, **kwargs):
            actual = execute(command, **kwargs)
            assert actual.acknowledgment.disposition == "registered"
            registered_receipts.append(actual)
            raise interruption

        mark("original activation dependencies")
        with monkeypatch.context() as patch:
            patch.setattr(session.delivery.venue, "execute", committed_then_interrupted)
            with pytest.raises(KeyboardInterrupt) as raised:
                session.activate_and_send(
                    operation_id="interrupted-activation",
                    attempt_ids=ids,
                    clock_reference=clock_reference,
                    quote_clock_reference=quote_clock_reference,
                )
        assert raised.value is interruption
        assert len(registered_receipts) == 1
        assert session.last_delivery_failure is None  # BaseException bypasses local recovery.
        original = pair.account.restore(case.scope)
        original_daily = case.h.resolved()
        assert tuple(item.state.value for item in original_daily.attempts) == ("in_flight",)
        original_hold = original_daily.obligations.bindings[0].commitment
        assert original_hold.reserved_cash > 0 and original_hold.filled_quantity == 0
        assert original.checkpoint.state.broker_events == ()
        assert original_daily.attempt_sources is not None
        original_activation = next(
            source
            for source in original_daily.attempt_sources.sources
            if source.coordinator_command_id == "interrupted-activation"
        )
        activation_bytes = runtime.codec.encode_record(original_activation)
        independent = session.delivery.venue.read()
        submissions = tuple(
            command
            for command in independent.state.commands
            if isinstance(command.payload, VenueSubmit)
        )
        assert len(submissions) == 1
        assert independent.state.accounting.broker_events == ()
        mark("committed independent send remains IN_FLIGHT")

        old_coordinator, old_daily, old_account = case.h.coordinator, case.h.store, pair.account
        old_lease = case.h.lease
        released = old_coordinator.release(old_lease.fence)
        assert released.fence == old_lease.fence
        # Only the declared coordinator fixture clock advances. Original quote,
        # clock and activation records keep their old timestamps and expiry.
        case.h.clock.instant = max(
            case.h.clock.instant, original_activation.valid_until
        ) + timedelta(milliseconds=1)
        case.h.coordinator = SqlAccountCoordinator(
            account_id=case.h.account,
            authority=SqlAccountCoordinatorAuthority(
                engine=case.engine,
                policy=old_coordinator._authority.policy,
                clock=case.h.clock,
            ),
        )
        case.h.lease = case.h.coordinator.acquire("explicit-uncertain-restart-owner")
        assert case.h.lease.fencing_generation == old_lease.fencing_generation + 1
        assert case.h.lease.owner_id != old_lease.owner_id
        restarted_runtime = fresh_reader(case, runtime)
        case.h.store = SqlDailyRuntimeRisk(
            case.engine,
            coordinator=case.h.coordinator,
            codec=restarted_runtime.codec,
            producers=restarted_runtime,
            accounting=restarted_runtime.accounting,
        )
        case.reader = restarted_runtime
        case.owner.runtime_evidence = restarted_runtime
        pair.restart()
        case.store = pair.account
        restarted_runtime.bind_stores(accounts=pair.account, daily=case.h.store)
        restarted_runtime.bind_reconciliation(pair.publisher)
        restarted = session_for(pair, restarted_runtime)
        assert case.h.store is not old_daily and pair.account is not old_account
        assert restarted.attempts is not session.attempts
        assert restarted.outcomes is not session.outcomes
        assert restarted.delivery is not session.delivery
        restored = pair.account.restore(case.scope)
        restored_daily = case.h.resolved()
        assert restored.receipt == original.receipt
        assert restored.checkpoint == original.checkpoint
        assert restored_daily.obligations == original_daily.obligations
        assert restored_daily.attempts == original_daily.attempts
        assert not restarted_runtime._active
        assert restarted.delivery.venue.read() == independent
        mark("new lease and reconstructed original owners")

        unknown_receipt = restarted.recover_in_flight(
            operation_id="restart-retained-unknown", attempt_ids=ids
        )
        uncertain = pair.account.restore(case.scope)
        uncertain_daily = case.h.resolved()
        assert uncertain.receipt == unknown_receipt
        assert (
            uncertain.receipt.fence_reference.fencing_generation == case.h.lease.fencing_generation
        )
        assert tuple(item.state.value for item in uncertain_daily.attempts) == ("unknown",)
        assert uncertain_daily.attempts[0].events[:-1] == original_daily.attempts[0].events
        assert uncertain_daily.attempts[0].events[-1].reason == "simulation_process_recovery"
        assert uncertain.checkpoint.state == original.checkpoint.state
        assert uncertain_daily.obligations == original_daily.obligations
        assert uncertain_daily.control == original_daily.control
        assert uncertain_daily.attempt_sources is not None
        retained_activation = next(
            source
            for source in uncertain_daily.attempt_sources.sources
            if source.coordinator_command_id == "interrupted-activation"
        )
        assert restarted_runtime.codec.encode_record(retained_activation) == activation_bytes
        assert retained_activation.valid_until < case.h.clock.instant
        assert runtime.codec.encode_record(clock_reference) == original_clock_bytes
        assert runtime.codec.encode_record(quote_clock_reference) == original_quote_clock_bytes
        assert restarted.delivery.venue.read() == independent
        mark("UNKNOWN published without any financial mutation")

        assert (
            restarted.observe_attempt(
                operation_id="registered-still-unknown",
                capture_id="restart-registered-capture",
                attempt_id=ids[0],
            )
            is None
        )
        assert pair.account.restore(case.scope).receipt == unknown_receipt
        assert case.h.resolved().obligations == original_daily.obligations

        def forbidden_resend(*_args, **_kwargs):
            raise AssertionError("reconstructed session attempted a second venue send")

        with monkeypatch.context() as patch:
            patch.setattr(restarted.delivery.venue, "execute", forbidden_resend)
            with pytest.raises(ValueError):
                restarted.activate_and_send(
                    operation_id="restart-denies-resend",
                    attempt_ids=ids,
                    clock_reference=clock_reference,
                    quote_clock_reference=quote_clock_reference,
                )
        assert restarted.delivery.venue.read() == independent
        assert len(registered_receipts) == 1
        mark("registered observation gives no acknowledgment or resend")

        # Explicit independent acceptance is a later modeled venue input. It
        # supplies an outcome only; no fill or canonical financial change occurs.
        case.h.clock.instant += timedelta(milliseconds=20)
        accepted = restarted.delivery.venue.execute(
            VenueCommand(
                "restart-independent-acceptance",
                case.h.clock.instant,
                VenueAccept(original_hold.order_id),
            )
        )
        assert accepted.acknowledgment.disposition == "applied"
        resolved_receipt = restarted.observe_attempt(
            operation_id="restart-captured-resolution",
            capture_id="restart-accepted-capture",
            attempt_id=ids[0],
        )
        assert resolved_receipt is not None
        final = pair.account.restore(case.scope)
        final_daily = case.h.resolved()
        assert final.receipt == resolved_receipt
        assert tuple(item.state.value for item in final_daily.attempts) == ("resolved",)
        assert final_daily.attempts[0].events[:-1] == uncertain_daily.attempts[0].events
        assert final.checkpoint.state == original.checkpoint.state
        assert final_daily.obligations == original_daily.obligations
        assert final_daily.control == original_daily.control
        assert (
            sum(
                isinstance(command.payload, VenueSubmit)
                for command in restarted.delivery.venue.read().state.commands
            )
            == 1
        )
        mark("later captured acceptance resolves metadata only")
    finally:
        fixture.close()
