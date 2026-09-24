"""Actual retained synthetic daily sources pass through coordinator composition."""

from dataclasses import fields, replace
from datetime import timedelta
from zoneinfo import ZoneInfo

import pytest

from packages.domain.continuous_quote_contracts import (
    ContinuousQuoteClosure,
    ContinuousQuoteSelection,
)
from packages.domain.forward_contracts import ForwardDataState, ForwardRequirement
from packages.domain.models import Side
from packages.persistence.continuous_frontier_publication import SqlContinuousFrontierPublication
from packages.persistence.continuous_runtime_sources import runtime_source_key
from tests.integration import test_continuous_runtime_sources as runtime_fixture
from tests.integration.test_personal_forward_capture_journal import capture, journal
from tests.unit.test_personal_forward_capture import Clock, Transport, quote_body, request

source = runtime_fixture.source


def fresh_frontier(source):
    case, original, _previous, _request, descriptor, resolved, _clock = source
    # A new actual owner graph restores the same committed account. The old
    # fixture descriptor remains retained history and is not an active callback
    # in this newly constructed runtime producer.
    reader = runtime_fixture.fresh_reader(case, original)
    case.h.store.producers = reader
    case.reader = reader
    case.owner.runtime_evidence = reader
    case.store = case.new_store()
    reader.bind_stores(accounts=case.store, daily=case.h.store)
    previous = case.store.restore(case.scope)
    assert previous is not None and resolved.plan.market is not None
    market = reader.forward_sources.resolve(resolved.plan.market.closure)
    assert descriptor.operating is not None
    return (
        case,
        SqlContinuousFrontierPublication(account=case.store),
        previous,
        market,
        descriptor.operating.clock_reference,
    )


def test_daily_coordinator_retains_original_sources_and_blocks_missing_reconciliation(source):
    case, publisher, previous, market, clock = fresh_frontier(source)
    before = previous.checkpoint
    prepared = publisher.prepare_daily(
        command_id="coordinator-original-daily",
        previous=previous,
        market=market,
        clock_reference=clock,
    )
    receipt = publisher.publish(prepared)
    restored = case.store.restore(case.scope)
    assert restored is not None and restored.receipt == receipt
    assert receipt.commit.sequence == previous.receipt.commit.sequence + 1
    assert receipt.commit.source_evidence.semantic_sha256 == market.closure.semantic_sha256
    (decision,) = restored.checkpoint.runtime_decisions[len(before.runtime_decisions) :]
    assert not decision.decision.approved
    assert decision.evidence.inputs.reconciliation is None
    assert decision.installed_commitments == ()
    assert restored.checkpoint.state.cash_flows == before.state.cash_flows
    assert restored.checkpoint.state.submissions == before.state.submissions
    current = case.h.resolved()
    assert current.admissions[-1].admission.decision == decision.decision
    assert not current.obligations.bindings
    with case.store.write_transaction() as connection:
        assert (
            case.store.retry_in_transaction(
                connection,
                original=restored,
                command_sha256=receipt.commit.transition.command_sha256,
                fence=case.h.lease.fence,
            )
            == receipt
        )


def test_daily_coordinator_rejects_copied_source_before_descriptor_append(source):
    _case, publisher, previous, market, clock = fresh_frontier(source)
    key = runtime_source_key(previous.receipt.commit.scope)
    before = publisher.runtime.journal.read_head(key)
    with pytest.raises(ValueError, match="OWNED_CAPTURE"):
        publisher.prepare_daily(
            command_id="copied-daily-source",
            previous=previous,
            market=replace(market),
            clock_reference=clock,
        )
    assert publisher.runtime.journal.read_head(key) == before


def test_quote_coordinator_advances_original_captured_mark_without_new_admission(source):
    case, original, _previous, _request, _descriptor, _resolved, _clock = source
    session = next(
        item
        for item in case.inputs.spec.calendar.sessions
        if item.session_label == case.inputs.spec.window.scored_sessions[1]
    )
    at = session.opens_at
    case.h.coordinator.release(case.h.lease.fence)
    case.h.clock.instant = at + timedelta(milliseconds=300)
    case.h.lease = case.h.coordinator.acquire("quote-coordinator-owner")
    reader = runtime_fixture.fresh_reader(case, original)
    case.h.store.producers = reader
    case.reader = reader
    case.owner.runtime_evidence = reader
    case.store = case.new_store()
    reader.bind_stores(accounts=case.store, daily=case.h.store)
    previous = case.store.restore(case.scope)
    assert previous is not None
    instrument_id, symbol = case.inputs.spec.instruments[0]
    assert symbol == "SPY"
    template = request()
    provider = replace(template.source, account_scope=case.h.account)
    captured_request = replace(
        template,
        capture_id="coordinator-original-quote",
        source=provider,
        instruments=(replace(template.instruments[0], instrument_id=instrument_id),),
        session=session.session_label,
        session_open=session.opens_at,
        session_close=session.closes_at,
        window_start=session.opens_at,
        window_end=session.closes_at,
        journal_key=replace(
            template.journal_key,
            account_scope=case.h.account,
            source_scope_sha256=provider.semantic_sha256,
        ),
    )
    initial = ForwardDataState((provider,), "recorded")
    stamp = at.astimezone(ZoneInfo("America/New_York")).strftime("%H:%M:%S %Z %m-%d-%Y")
    publication = capture(
        captured_request,
        initial,
        journal(case.engine),
        case.artifacts,
        clock=Clock(at),
        transport=Transport(
            quote_body(
                dateTimeUTC=int(at.timestamp()),
                All={"bid": 99, "ask": 100, "bidTime": stamp, "askTime": stamp},
            )
        ),
    )
    closure = ContinuousQuoteClosure(
        account_id=case.h.account,
        closure_id="coordinator-quote-frontier",
        initial_state=initial,
        publications=(publication,),
        selections=(
            ContinuousQuoteSelection(
                publication.record.observations[0].observation_id,
                ForwardRequirement(provider.source_id, instrument_id, symbol, at.date(), "quote"),
                Side.BUY,
                captured_request.producer,
            ),
        ),
        admitted_at=case.h.clock.instant,
        boot_id=publication.record.receipt.boot_id,
        admitted_monotonic_ns=1300000000,
        evidence_class="synthetic_fixture",
    )
    market = reader.forward_sources.resolve(closure)
    publisher = SqlContinuousFrontierPublication(account=case.store)
    before = case.h.resolved()
    prepared = publisher.prepare_quote(
        command_id="original-quote-publication", previous=previous, market=market
    )
    receipt = publisher.publish(prepared)
    restored = case.store.restore(case.scope)
    after = case.h.resolved()
    assert restored is not None and restored.receipt == receipt
    assert restored.checkpoint.runtime_decisions == previous.checkpoint.runtime_decisions
    # The sole engine updates marks, command history and its source barrier.
    # Quote publication cannot create cash flows, orders, fills or commitments.
    for field in fields(previous.checkpoint.state):
        if field.name not in {"marks", "commands", "halted", "revision"}:
            assert getattr(restored.checkpoint.state, field.name) == getattr(
                previous.checkpoint.state, field.name
            )
    assert after.admissions == before.admissions
    assert after.obligations == before.obligations
    assert after.control == before.control
    assert receipt.commit.source_evidence.semantic_sha256 == closure.semantic_sha256
    mark = restored.request.events[0].payload.payload
    assert mark.price == 100 and mark.basis == "runtime_quote_ask_v1"
    assert mark.knowledge_at == publication.record.receipt.validated_at
    assert mark.economic_at == publication.record.observations[0].payload.ask_at
