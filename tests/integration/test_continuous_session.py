"""Finite actual owner routing with explicit synthetic captures, time and controls.

HALTED cases use genuine retained signed-owner history. The activation fixture's
operational re-arm remains explicitly modeled; it is not owner readiness proof.
"""

from copy import copy
from dataclasses import replace
from datetime import timedelta
from threading import Event

import pytest
import sqlalchemy as sa

from apps.trader.continuous_session import ContinuousSessionCoordinator, ContinuousSessionStopped
from packages.domain.operational_control import OperationalControlState
from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.persistence.applied_reconciliation_schema import applied_reconciliation_commits
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_attempt_outcome_sources import (
    SqlContinuousAttemptOutcomeSources,
)
from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication
from packages.persistence.continuous_observed_hold_sources import SqlContinuousObservedHoldSources
from packages.persistence.continuous_runtime_attempt_sources import (
    SqlContinuousRuntimeAttemptSources,
)
from packages.persistence.continuous_simulation_delivery import SqlContinuousSimulationDelivery
from packages.persistence.continuous_venue_sources import SqlContinuousVenueSources
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.stateful_venue import SqlStatefulVenue
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
from tests.integration import test_continuous_runtime_attempt_sources as attempt_fixture
from tests.integration.test_continuous_reconciliation_publication import PublicationCase
from tests.integration.test_continuous_session_owner_startup import genuine_captured_selection


class SharedModeledCaptureClock:
    """A named fixture clock shared with the synthetic coordinator clock."""

    def __init__(self, clock):
        self.clock = clock

    def __call__(self):
        self.clock.instant += timedelta(microseconds=1)
        return self.clock.instant


def canonical_accounting(monkeypatch):
    restart = PublicationCase.restart

    def actual_owner(pair):
        pair.accounting = pair.base.owner.accounting
        restart(pair)

    monkeypatch.setattr(PublicationCase, "restart", actual_owner)


def session_for(pair, runtime, reader=None):
    case = pair.base
    if reader is None:
        reader = SqlContinuousRuntimeAttemptSources(
            case.engine,
            accounts=pair.account,
            preparer=case.owner,
            daily=case.h.store,
            runtime_sources=runtime,
            artifacts=case.artifacts,
            codec=runtime.codec,
        )
        runtime.bind_attempt_sources(reader)
    observed = SqlContinuousObservedHoldSources(
        case.engine,
        accounts=pair.account,
        preparer=case.owner,
        venue_sources=pair.sources,
        daily=case.h.store,
        artifacts=case.artifacts,
        codec=runtime.codec,
    )
    runtime.bind_observed_hold_sources(observed)
    publisher = SqlContinuousAttemptPublication(account=pair.account)
    delivery = SqlContinuousSimulationDelivery(publisher=publisher, sources=reader)
    independent = pair.venue
    venue = SqlStatefulVenue(
        independent.journal._engine,
        model=runtime.venue_model,
        artifacts=independent.artifacts,
        codec=runtime.codec,
        accounting=runtime.accounting,
        verified_sources=delivery,
    )
    delivery.bind_venue(venue)
    scope = ReconciliationScope(
        runtime.venue_model.account_id,
        runtime.venue_model.venue_id,
        "stateful_simulation",
        runtime.venue_reference.semantic_sha256_ref,
        "stateful_simulation",
    )
    outcomes = SqlContinuousAttemptOutcomeSources(
        attempts=reader,
        venue=venue,
        capture=SqlVenueReconciliationCapture(
            case.engine,
            artifacts=case.artifacts,
            codec=runtime.codec,
            clock=SharedModeledCaptureClock(case.h.clock),
        ),
        venue_sources=SqlContinuousVenueSources(
            case.engine,
            artifacts=case.artifacts,
            codec=runtime.codec,
            scope=scope,
            model=runtime.venue_model,
            resolver=pair.sources.resolver,
        ),
    )
    reader.bind_outcome_sources(outcomes)
    return ContinuousSessionCoordinator(
        account=pair.account, delivery=delivery, outcomes=outcomes, stop_event=Event()
    )


def financial_counts(pair):
    with pair.base.engine.connect() as connection:
        return tuple(
            connection.scalar(sa.select(sa.func.count()).select_from(table))
            for table in (
                continuous_account_commits,
                applied_reconciliation_commits,
                *DAILY_RUNTIME_TABLES,
            )
        )


@pytest.fixture
def halted(tmp_path, monkeypatch):
    canonical_accounting(monkeypatch)
    fixture, *_ = genuine_captured_selection(tmp_path, monkeypatch)
    pair, _, runtime, *_ = fixture
    try:
        yield pair, session_for(pair, runtime)
    finally:
        pair.close()


def test_genuine_halted_session_reconciles_through_original_owners(halted):
    pair, session = halted
    original = pair.account.restore(pair.base.scope)
    control = pair.base.h.resolved().control
    assert control.effective_state is OperationalControlState.HALTED
    pair.base.h.clock.instant += timedelta(milliseconds=10)
    receipt = session.reconcile(operation_id="finite-observe", capture_id="finite-capture")
    restored = pair.account.restore(pair.base.scope)
    assert restored.receipt == receipt.continuous
    assert restored.checkpoint.state.cash_flows == original.checkpoint.state.cash_flows
    assert pair.base.h.resolved().control == control
    assert session.attempt_publisher is session.delivery.publisher
    assert session.last_delivery_failure is None


def test_stop_denies_every_entry_and_cannot_be_cleared(halted, monkeypatch):
    pair, session = halted
    before = financial_counts(pair)
    calls = (
        lambda: session.publish_daily(
            operation_id="stopped-daily", market=None, clock_reference=None
        ),
        lambda: session.publish_pending(operation_id="stopped-pending", admission_command_id="a"),
        lambda: session.publish_quote(operation_id="stopped-quote", market=None),
        lambda: session.reconcile(operation_id="stopped-observe", capture_id="a"),
        lambda: session.activate_and_send(
            operation_id="stopped-send",
            attempt_ids=("a",),
            clock_reference=None,
            quote_clock_reference=None,
        ),
        lambda: session.observe_attempt(
            operation_id="stopped-outcome", attempt_id="a", capture_id="a"
        ),
        lambda: session.recover_in_flight(operation_id="stopped-recover", attempt_ids=("a",)),
        lambda: session.expire_unsent(operation_id="stopped-expire", attempt_id="a"),
    )
    session.stop_event.set()
    monkeypatch.setattr(session.stop_event, "is_set", lambda: False)
    for call in calls:
        with pytest.raises(ContinuousSessionStopped):
            call()
        session.stop_event.clear()
    assert financial_counts(pair) == before


def test_session_rejects_copied_graph_and_copied_owned_source(halted, monkeypatch):
    pair, session = halted
    before = financial_counts(pair)
    with pytest.raises(ValueError, match="OWNERS"):
        ContinuousSessionCoordinator(
            account=pair.account,
            delivery=copy(session.delivery),
            outcomes=session.outcomes,
            stop_event=Event(),
        )
    with pytest.raises(ValueError, match="OWNERS_CHANGED"):
        copy(session).reconcile(operation_id="copied-session", capture_id="copied-capture")
    capture = session.registrations.capture

    def copied(**kwargs):
        return replace(capture(**kwargs))

    monkeypatch.setattr(session.registrations, "capture", copied)
    with pytest.raises(ValueError, match=r"OWNED|original|ORIGINAL"):
        session.reconcile(operation_id="copied-source", capture_id="copied-source-capture")
    assert financial_counts(pair) == before


def test_stop_after_real_preparation_denies_publication(halted, monkeypatch):
    pair, session = halted
    before = financial_counts(pair)
    prepare = session.observed.prepare

    def stopped(**kwargs):
        actual = prepare(**kwargs)
        session.stop_event.set()
        return actual

    monkeypatch.setattr(session.observed, "prepare", stopped)
    with pytest.raises(ContinuousSessionStopped):
        session.reconcile(operation_id="stopped-prepared", capture_id="stopped-captured")
    assert financial_counts(pair) == before


def test_stop_after_actual_applied_write_rolls_back_before_outer_commit(halted, monkeypatch):
    pair, session = halted
    before = financial_counts(pair)
    commit = session.observed.publisher.applied.commit_in_transaction

    def stopped(connection, **kwargs):
        actual = commit(connection, **kwargs)
        session.stop_event.set()
        return actual

    monkeypatch.setattr(session.observed.publisher.applied, "commit_in_transaction", stopped)
    with pytest.raises(ContinuousSessionStopped):
        session.reconcile(
            operation_id="stop-after-applied", capture_id="stop-after-applied-capture"
        )
    assert financial_counts(pair) == before
    session.stop_event.clear()
    with pytest.raises(ContinuousSessionStopped):
        session.reconcile(operation_id="no-stop-reset", capture_id="no-stop-reset-capture")


def test_pending_uses_actual_admission_and_rejects_invalid_groups(tmp_path, monkeypatch):
    canonical_accounting(monkeypatch)
    fixture = attempt_fixture.attempt_case.__wrapped__(tmp_path, monkeypatch)
    try:
        case, runtime, reader, _previous, _current, admission = next(fixture)
        pair = case.paired_fixture
        session = session_for(pair, runtime, reader)
        receipt = session.publish_pending(
            operation_id="finite-pending", admission_command_id=admission.command_id
        )
        restored = case.store.restore(case.scope)
        current = case.h.resolved()
        assert restored.receipt == receipt
        assert current.attempts and all(item.state.value == "pending" for item in current.attempts)
        assert (
            session.daily.inspect_snapshot_admissions(current)[0].admission == admission.admission
        )
        before = financial_counts(pair)
        for ids in ((), ("a",) * 2, tuple(str(i) for i in range(5))):
            with pytest.raises(ValueError, match="ATTEMPT_GROUP"):
                session.recover_in_flight(operation_id="invalid-group", attempt_ids=ids)
        with pytest.raises(ValueError):
            session.publish_pending(
                operation_id="duplicate-pending", admission_command_id=admission.command_id
            )
        assert financial_counts(pair) == before
    finally:
        fixture.close()


@pytest.mark.parametrize("failure_kind", ["lost_ack", "rejected"])
def test_actual_activation_failed_send_is_not_retried_and_retains_unknown(
    tmp_path, monkeypatch, failure_kind
):
    canonical_accounting(monkeypatch)
    fixture = attempt_fixture.attempt_case.__wrapped__(tmp_path, monkeypatch)
    try:
        initial = next(fixture)
        case, runtime, reader, _previous, current, _admission, _source, descriptor = (
            attempt_fixture.activation_preparation(initial)
        )
        session = session_for(case.paired_fixture, runtime, reader)
        actual = session.delivery.venue.execute
        failures = []
        original_error = OSError("explicit synthetic lost acknowledgment")

        def lost(command, **kwargs):
            failures.append(command.command_id)
            if failure_kind == "lost_ack":
                actual(command, **kwargs)
                raise original_error
            # Advance the declared synthetic coordinator clock only after the
            # first send check. The original source deadline is unchanged; the
            # actual venue verification rejects and retains that command ACK.
            case.h.clock.instant = _source.source.valid_until + timedelta(milliseconds=1)
            return actual(command, **kwargs)

        monkeypatch.setattr(session.delivery.venue, "execute", lost)
        ids = tuple(sorted(item.attempt_id for item in current.attempts))
        clock_ref = descriptor.plan.operating.clock_reference
        quote_clock = descriptor.plan.quote_clock.reference
        with pytest.raises(OSError if failure_kind == "lost_ack" else ValueError) as error:
            session.activate_and_send(
                operation_id="finite-activation",
                attempt_ids=ids,
                clock_reference=clock_ref,
                quote_clock_reference=quote_clock,
            )
        if failure_kind == "lost_ack":
            assert error.value is original_error
        else:
            assert str(error.value) == "CONTINUOUS_SESSION_REGISTRATION_REJECTED"
        assert len(failures) == 1
        failure = session.last_delivery_failure
        if failure_kind == "lost_ack":
            assert failure.returned_receipts == ()
        else:
            assert len(failure.returned_receipts) == 1
            assert failure.returned_receipts[0].acknowledgment.disposition == "rejected"
        assert not failure.recovery_failed and failure.unknown_receipt is not None
        assert all(item.state.value == "unknown" for item in case.h.resolved().attempts)
        assert case.store.restore(case.scope).receipt == failure.unknown_receipt
        with pytest.raises(ValueError):
            session.activate_and_send(
                operation_id="no-resend",
                attempt_ids=ids,
                clock_reference=clock_ref,
                quote_clock_reference=quote_clock,
            )
        assert len(failures) == 1
    finally:
        fixture.close()
