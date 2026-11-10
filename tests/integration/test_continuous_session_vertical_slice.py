"""One public coordinator path over fresh, live-disabled synthetic account stores.

Captured market responses, clocks and operational re-arm are explicitly modeled
by the existing fixtures. Strategy, risk, attempts, independent venue records and
financial publications use their actual owners. Restart reconstructs owners in
process; this is neither provider qualification nor an OS process-crash test.
"""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from packages.domain.continuous_quote_contracts import (
    CONTINUOUS_QUOTE_CLOSURE_SCHEMA,
    ContinuousQuoteClosure,
    ContinuousQuoteSelection,
)
from packages.domain.forward_capture_contracts import CaptureClockSample
from packages.domain.forward_contracts import ForwardDataState, ForwardRequirement
from packages.domain.operational_control import OperationalControlState
from packages.domain.research_dataset import modeled_daily_availability
from packages.domain.runtime_operating_contracts import CLOCK_SCHEMA, RuntimeClockObservation
from packages.domain.stateful_venue_contracts import (
    VenueAccept,
    VenueCommand,
    VenueRunDue,
    VenueSubmit,
)
from packages.persistence.continuous_forward_sources import ContinuousForwardSourceError
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.runtime_operating_evidence import SqlRuntimeOperatingEvidence
from packages.persistence.runtime_owner_dependencies import SqlRuntimeOwnerDependencies
from tests.integration.test_continuous_runtime_sources import fresh_reader
from tests.integration.test_continuous_session import (
    canonical_accounting,
    financial_counts,
    session_for,
)
from tests.integration.test_continuous_session_acceptance import compare_economics
from tests.integration.test_continuous_session_owner_startup import genuine_captured_selection
from tests.integration.test_personal_forward_capture_journal import capture, journal
from tests.integration.test_runtime_owner_dependencies import attach
from tests.unit.test_personal_forward_capture import Clock, Transport, quote_body, request
from tests.unit.test_runtime_operating_evidence import healthy_sampler
from tests.unit.test_stateful_venue import quote


def _mark(step):
    print(f"session vertical slice: {step}", flush=True)


def _append_clock(session, sample):
    operating = session.runtime.operating
    prepared = operating.prepare_clock_append(
        sample, expected_head=operating.journal.read_head(operating.clock_key())
    )
    with session.account.write_transaction() as connection:
        return operating.append_clock_in_transaction(connection, prepared)


def _rebind_owner_dependencies(pair, runtime, previous_runtime):
    """Reconstruct the current graph while retaining signed command authority."""
    previous = previous_runtime.owner_dependencies
    assert previous is not None
    case = pair.base
    reader = SqlRuntimeOwnerDependencies(
        case.engine,
        accounts=pair.account,
        daily=case.h.store,
        publisher=pair.publisher,
        commands=previous.commands,
        artifacts=case.artifacts,
        codec=runtime.codec,
    )
    runtime.bind_owner_dependencies(reader)
    assert runtime.owner_dependencies is reader and reader is not previous
    assert reader.accounts is pair.account and reader.accounts is not previous.accounts
    assert reader.daily is case.h.store and reader.publisher is pair.publisher
    assert reader.producer is runtime
    assert reader.commands is previous.commands
    assert reader.commands.authenticator is previous.commands.authenticator


def _publish_execution_quote(pair, runtime):
    """Retain a synthetic quote through the public session, preserving old times."""
    _mark("quote setup")
    case, h = pair.base, pair.base.h
    previous = pair.account.restore(case.scope)
    (order,) = previous.checkpoint.state.commitments
    quote_at = order.not_before
    cutoff = quote_at + timedelta(milliseconds=300)
    h.coordinator.release(h.lease.fence)
    h.clock.instant = quote_at - timedelta(seconds=10)
    h.lease = h.coordinator.acquire("vertical-slice-execution-owner")
    clock, sampler, sample = healthy_sampler(case.scope, at=cutoff)
    operating = SqlRuntimeOperatingEvidence(
        case.engine,
        journal=SqlDurableJournal(
            case.engine, codec=runtime.codec, record_types={CLOCK_SCHEMA: RuntimeClockObservation}
        ),
        artifacts=case.artifacts,
        codec=runtime.codec,
        clock_sampler=sampler,
    )
    previous_runtime = runtime
    runtime = fresh_reader(
        case,
        SimpleNamespace(
            operating=operating,
            accounting=runtime.accounting,
            strategy=runtime.strategy,
            venue_model=runtime.venue_model,
            venue_reference=runtime.venue_reference,
            producer_map=runtime.producer_map,
            benchmark_instrument_id=runtime.benchmark_instrument_id,
        ),
    )
    h.store.producers = runtime
    case.reader = runtime
    case.owner.runtime_evidence = runtime
    pair.restart()
    case.store = pair.account
    runtime.bind_stores(accounts=pair.account, daily=h.store)
    runtime.bind_reconciliation(pair.publisher)
    _rebind_owner_dependencies(pair, runtime, previous_runtime)
    session = session_for(pair, runtime)
    h.clock.instant = cutoff
    calendar = next(
        item
        for item in case.inputs.spec.calendar.sessions
        if item.session_label == order.execution_session
    )
    template = request()
    source = replace(template.source, account_scope=h.account)
    selected = replace(
        template,
        capture_id="vertical-slice-quote-response",
        source=source,
        instruments=(replace(template.instruments[0], instrument_id=order.instrument_id),),
        session=calendar.session_label,
        session_open=calendar.opens_at,
        session_close=calendar.closes_at,
        window_start=calendar.opens_at,
        window_end=calendar.closes_at,
        journal_key=replace(
            template.journal_key,
            account_scope=h.account,
            source_scope_sha256=source.semantic_sha256,
        ),
    )
    state = ForwardDataState((source,), "recorded")
    stamp = quote_at.astimezone(ZoneInfo("America/New_York")).strftime("%H:%M:%S %Z %m-%d-%Y")
    publication = capture(
        selected,
        state,
        journal(case.engine),
        case.artifacts,
        clock=Clock(
            quote_at,
            samples=tuple(
                CaptureClockSample(
                    quote_at + timedelta(milliseconds=n),
                    clock.mono - 300_000_000 + n * 1_000_000,
                    clock.epoch,
                )
                for n in (0, 100, 200)
            ),
        ),
        transport=Transport(
            quote_body(
                dateTimeUTC=int(quote_at.timestamp()),
                All={"bid": 99, "ask": 100, "bidTime": stamp, "askTime": stamp},
            )
        ),
    )
    closure = ContinuousQuoteClosure(
        account_id=h.account,
        closure_id="vertical-slice-quote",
        initial_state=state,
        publications=(publication,),
        selections=(
            ContinuousQuoteSelection(
                publication.record.observations[0].observation_id,
                ForwardRequirement(
                    source.source_id,
                    order.instrument_id,
                    order.symbol,
                    calendar.session_label,
                    "quote",
                ),
                order.side,
                selected.producer,
            ),
        ),
        admitted_at=cutoff,
        boot_id=clock.epoch,
        admitted_monotonic_ns=clock.mono,
        evidence_class="synthetic_fixture",
    )
    prior = pair.account.restore(case.scope)
    market = case.forward.resolve(closure)
    before_counts = financial_counts(pair)
    before_venue_head = session.delivery.venue.read().head
    with pytest.raises(
        ContinuousForwardSourceError, match=r"^OWNED_CAPTURE_SOURCE_RESOLUTION_REQUIRED$"
    ):
        session.publish_quote(
            operation_id="vertical-slice-deny-copied-quote", market=replace(market)
        )
    assert financial_counts(pair) == before_counts
    assert session.delivery.venue.read().head == before_venue_head
    _mark("unowned quote denied without financial mutation")
    receipt = session.publish_quote(operation_id="vertical-slice-publish-quote", market=market)
    quoted = pair.account.restore(case.scope)
    assert quoted.receipt == receipt
    assert receipt.commit.source_evidence.schema_id == CONTINUOUS_QUOTE_CLOSURE_SCHEMA
    assert receipt.commit.source_evidence.semantic_sha256 == closure.semantic_sha256
    assert quoted.checkpoint.runtime_decisions == prior.checkpoint.runtime_decisions
    _mark("quote published")
    quote_clock = _append_clock(session, sample)

    # Fresh independent observations bind reconciliation to the pending heads;
    # repeated equal views alone are not used to clear an uncertain attempt.
    for index in range(2):
        clock.advance(0.02)
        h.clock.instant = clock.at
        session.delivery.venue.execute(
            VenueCommand(f"vertical-slice-pending-tick-{index}", h.clock.instant, VenueRunDue())
        )
        session.reconcile(
            operation_id=f"vertical-slice-pending-reconcile-{index}",
            capture_id=f"vertical-slice-pending-capture-{index}",
        )
        clock.advance((h.clock.instant - clock.at).total_seconds())
    assert pair.restore().reconciliation.resolved.result.status == "converged"
    current_clock = _append_clock(session, sampler.sample())
    _mark("quote dependencies reconciled")
    return session, runtime, clock, current_clock, quote_clock


def test_captured_session_public_path_reconciles_and_restarts_without_resend(tmp_path, monkeypatch):
    _mark("fresh signed setup start")
    canonical_accounting(monkeypatch)
    fixture, _prior, enabled, _initial_request, _enable_request = genuine_captured_selection(
        tmp_path, monkeypatch
    )
    pair = fixture[0]
    case, h = pair.base, pair.base.h
    try:
        _mark("fresh signed setup ready")
        assert not enabled.live_authorized
        assert h.resolved().control.effective_state is OperationalControlState.HALTED
        day = case.inputs.spec.window.scored_sessions[0]
        at = modeled_daily_availability(day) + timedelta(milliseconds=50)
        h.coordinator.release(h.lease.fence)
        h.clock.instant = h.decision_at = at
        h.lease = h.coordinator.acquire("vertical-slice-daily-owner")
        _owners, runtime, *_ = attach(pair)
        h.assignment = enabled
        # Existing synthetic verifier re-arms the actual control repository.
        # Preserve the already signed assignment instead of an unsigned install.
        with monkeypatch.context() as patch:
            patch.setattr(h, "install", lambda _assignment: None)
            h.enable()
        assert h.resolved().assignment == enabled
        assert not h.resolved().assignment.live_authorized
        _mark("explicit modeled rearm")
        session = session_for(pair, runtime)
        for index in range(2):
            h.clock.instant += timedelta(milliseconds=1)
            session.delivery.venue.execute(
                VenueCommand(f"vertical-slice-cash-tick-{index}", h.clock.instant, VenueRunDue())
            )
            session.reconcile(
                operation_id=f"vertical-slice-cash-reconcile-{index}",
                capture_id=f"vertical-slice-cash-capture-{index}",
            )
        _mark("cash reconciled")
        before = pair.account.restore(case.scope)
        h.clock.instant += timedelta(milliseconds=1)
        publication = case.add_capture(day)
        closure = case.closure(
            "vertical-slice-daily-source",
            h.clock.instant,
            tuple(item.observation_id for item in publication.record.observations),
        )
        _mark("captured daily inputs")
        daily_clock = _append_clock(session, runtime.operating.clock_sampler.sample())
        receipt = session.publish_daily(
            operation_id="vertical-slice-publish-daily",
            market=runtime.forward_sources.resolve(closure),
            clock_reference=daily_clock,
        )
        daily = pair.account.restore(case.scope)
        assert daily.receipt == receipt
        (decision,) = daily.checkpoint.runtime_decisions[len(before.checkpoint.runtime_decisions) :]
        assert decision.decision.approved, decision.decision.reasons
        (order,) = decision.installed_commitments
        assert daily.checkpoint.state.commitments == (order,)
        (admission,) = h.store.inspect_snapshot_admissions(h.resolved())
        assert admission.admission.decision == decision.decision
        _mark("daily decision and admission")
        pending_receipt = session.publish_pending(
            operation_id="vertical-slice-publish-pending", admission_command_id=admission.command_id
        )
        assert pair.account.restore(case.scope).receipt == pending_receipt
        (attempt,) = h.resolved().attempts
        assert attempt.state.value == "pending"
        assert attempt.preparation.original_admission == admission.admission
        _mark("pending attempt")

        session, runtime, clock, current_clock, quote_clock = _publish_execution_quote(
            pair, runtime
        )
        receipts = session.activate_and_send(
            operation_id="vertical-slice-send",
            attempt_ids=(attempt.attempt_id,),
            clock_reference=current_clock,
            quote_clock_reference=quote_clock,
        )
        assert len(receipts) == 1 and receipts[0].acknowledgment.disposition == "registered"
        assert session.last_delivery_failure is None
        _mark("simulated send registered")
        venue = session.delivery.venue
        (submission,) = tuple(
            item for item in venue.read().state.commands if isinstance(item.payload, VenueSubmit)
        )
        assert submission.payload.registration.submission.order_id == order.order_id
        assert h.resolved().attempts[0].attempt_id == attempt.attempt_id
        registered = pair.account.restore(case.scope)
        obligations = h.resolved().obligations
        assert (
            session.observe_attempt(
                operation_id="vertical-slice-registration-only",
                capture_id="vertical-slice-registered-capture",
                attempt_id=attempt.attempt_id,
            )
            is None
        )
        assert pair.account.restore(case.scope).receipt == registered.receipt
        assert h.resolved().obligations == obligations

        clock.advance(0.02)
        h.clock.instant = clock.at
        venue.execute(
            VenueCommand("vertical-slice-accept", h.clock.instant, VenueAccept(order.order_id))
        )
        policy = runtime.venue_model.execution_policy
        initial_cash = runtime.venue_model.initial_cash_flow.amount
        price = Decimal(100) * (1 + policy.slippage_bps / Decimal(10000))
        assert order.original_quantity > 1
        for index, quantity in enumerate((Decimal(1), order.original_quantity - 1)):
            clock.advance(0.02)
            h.clock.instant = clock.at
            modeled = quote(
                h.clock.instant, name=f"vertical-slice-fill-{index}", budget=str(quantity)
            )
            modeled = replace(
                modeled,
                observation=replace(
                    modeled.observation,
                    payload=replace(modeled.observation.payload, instrument_id=order.instrument_id),
                ),
            )
            venue.execute(
                VenueCommand(f"vertical-slice-fill-command-{index}", h.clock.instant, modeled)
            )
            if index == 0:
                assert (
                    session.observe_attempt(
                        operation_id="vertical-slice-confirm",
                        capture_id="vertical-slice-confirm-capture",
                        attempt_id=attempt.attempt_id,
                    )
                    is not None
                )
                assert h.resolved().attempts[0].state.value == "confirmed"
            session.reconcile(
                operation_id=f"vertical-slice-reconcile-fill-{index}",
                capture_id=f"vertical-slice-fill-capture-{index}",
            )
            retained, snapshot = compare_economics(session)
            filled = Decimal(1) if index == 0 else order.original_quantity
            assert snapshot.positions[0].quantity == filled
            assert snapshot.fees == filled * policy.fee_per_share
            assert snapshot.trade_date_cash == initial_cash - filled * (
                price + policy.fee_per_share
            )
            assert snapshot.settled_cash == initial_cash
            (binding,) = h.resolved().obligations.bindings
            hold = binding.commitment
            assert hold.remaining_quantity == order.original_quantity - filled
            if index == 0:
                assert hold.reserved_cash > 0
            else:
                assert hold.state == "terminal" and hold.reserved_cash == 0
            clock.advance((h.clock.instant - clock.at).total_seconds())
            _mark(
                "partial financial reconciliation"
                if index == 0
                else "complete financial reconciliation"
            )

        final, final_daily, independent = retained, h.resolved(), venue.read()
        _mark("restart reconstruction start")
        restarted_runtime = fresh_reader(case, runtime)
        h.store.producers = restarted_runtime
        case.reader = restarted_runtime
        case.owner.runtime_evidence = restarted_runtime
        pair.restart()
        case.store = pair.account
        restarted_runtime.bind_stores(accounts=pair.account, daily=h.store)
        restarted_runtime.bind_reconciliation(pair.publisher)
        _rebind_owner_dependencies(pair, restarted_runtime, runtime)
        restarted = session_for(pair, restarted_runtime)
        assert restarted.account is not session.account
        assert restarted.attempts is not session.attempts
        assert not restarted_runtime._active
        restored = pair.account.restore(case.scope)
        assert restored.receipt == final.receipt and restored.checkpoint == final.checkpoint
        assert h.resolved().attempts == final_daily.attempts
        assert h.resolved().obligations == final_daily.obligations
        assert not h.resolved().assignment.live_authorized
        assert restarted.delivery.venue.read() == independent
        _mark("restart retained state")
        with pytest.raises(ValueError):
            restarted.activate_and_send(
                operation_id="vertical-slice-deny-resend",
                attempt_ids=(attempt.attempt_id,),
                clock_reference=current_clock,
                quote_clock_reference=quote_clock,
            )
        assert restarted.delivery.venue.read() == independent
        restarted.reconcile(
            operation_id="vertical-slice-overlapping-view", capture_id="vertical-slice-overlap"
        )
        repeated, _ = compare_economics(restarted)
        assert repeated.checkpoint.state.cash_flows == final.checkpoint.state.cash_flows
        assert repeated.checkpoint.state.broker_events == final.checkpoint.state.broker_events
        assert repeated.checkpoint.state.commitments == final.checkpoint.state.commitments
        assert h.resolved().obligations == final_daily.obligations
        assert restarted.delivery.venue.read() == independent
        _mark("restart resend denied and overlapping view idempotent")
    finally:
        pair.close()
