"""Actual C/B/A first-send owners and independent SQLite venue; synthetic inputs."""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication
from packages.persistence.continuous_simulation_delivery import SqlContinuousSimulationDelivery
from packages.persistence.stateful_venue import SqlStatefulVenue
from tests.integration import test_continuous_runtime_attempt_sources as source_fixture

attempt_case = source_fixture.attempt_case


def activated_delivery(attempt_case):
    case, service, reader, _previous, _current, _admission, source, descriptor = (
        source_fixture.activation_preparation(attempt_case)
    )
    publisher = SqlContinuousAttemptPublication(account=case.store)
    with pytest.raises(ValueError):
        publisher.prepare_source(replace(source), sources=reader)
    prepared = publisher.prepare_source(source, sources=reader)
    batch = publisher.publish_dispatch(prepared, fence=case.h.lease.fence)
    delivery = SqlContinuousSimulationDelivery(publisher=publisher, sources=reader)
    independent = case.paired_fixture.venue
    venue = SqlStatefulVenue(
        independent.journal._engine,
        model=delivery.model,
        artifacts=independent.artifacts,
        codec=service.codec,
        accounting=service.accounting,
        verified_sources=delivery,
    )
    delivery.bind_venue(venue)
    return case, source, descriptor, publisher, batch, delivery, venue


def test_first_send_requires_actual_commit_and_uses_current_activated_reserve_terms(attempt_case):
    case, source, _descriptor, publisher, batch, delivery, venue = activated_delivery(attempt_case)
    attempt_id = source.envelopes[0].event.attempt_id
    before = venue.read()
    with pytest.raises(ValueError):
        delivery.deliver(replace(batch), source=source, attempt_id=attempt_id)
    with pytest.raises(ValueError):
        delivery.deliver(batch, source=replace(source), attempt_id=attempt_id)
    with pytest.raises(ValueError, match="ALREADY_ATTEMPTED"):
        publisher.publish_dispatch(batch.account, fence=case.h.lease.fence)
    receipt = delivery.deliver(batch, source=source, attempt_id=attempt_id)
    assert receipt.acknowledgment.disposition == "registered"
    after = venue.read()
    assert after.state.sequence == before.state.sequence + 1
    packet = after.state.commands[-1].payload
    commitment = next(
        item
        for item in batch.attempts.result.accounting_state.commitments
        if item.commitment_id == packet.registration.source_commitment.commitment_id
    )
    assert packet.registration.source_commitment == commitment
    assert commitment.state == "active"
    assert after.state.accounting.cash_flows == before.state.accounting.cash_flows
    with pytest.raises(ValueError, match="ALREADY_CONSUMED"):
        delivery.deliver(batch, source=source, attempt_id=attempt_id)
    with pytest.raises(ValueError, match="ONE_USE"):
        delivery.verify_submission(venue.model, packet, received_at=after.state.as_of)
    assert venue.read().head == after.head
    # A venue response alone has not published any canonical observed outcome.
    assert all(item.state.value == "in_flight" for item in case.h.resolved().attempts)


def test_lost_venue_acknowledgment_keeps_in_flight_and_cannot_resend(attempt_case, monkeypatch):
    case, source, _descriptor, _publisher, batch, delivery, venue = activated_delivery(attempt_case)
    attempt_id = source.envelopes[0].event.attempt_id
    before = venue.read()
    execute = venue.execute
    calls = []

    def lost(command, **kwargs):
        calls.append(command.command_id)
        execute(command, **kwargs)
        raise OSError("synthetic acknowledgment loss")

    monkeypatch.setattr(venue, "execute", lost)
    with pytest.raises(OSError, match="acknowledgment loss"):
        delivery.deliver(batch, source=source, attempt_id=attempt_id)
    assert venue.read().state.sequence == before.state.sequence + 1
    with pytest.raises(ValueError, match="ALREADY_CONSUMED"):
        delivery.deliver(batch, source=source, attempt_id=attempt_id)
    assert len(calls) == 1
    assert all(item.state.value == "in_flight" for item in case.h.resolved().attempts)
    assert case.h.resolved().obligations == batch.attempts.result.obligations
    # Recovery remains possible after the send's original validity expires.
    # Recording uncertainty must neither renew that validity nor release money.
    case.h.clock.instant = source.source.valid_until + timedelta(milliseconds=1)
    previous = case.store.restore(case.scope)
    current = case.h.resolved()
    unknown = delivery.sources.retain_unknown(
        coordinator_command_id="lost-acknowledgment-unknown",
        previous=previous,
        current=current,
        admissions=source.admissions,
        attempt_ids=(attempt_id,),
        reason="venue_acknowledgment_lost",
        dispatch_keys=source.closure.dispatch_keys,
    )
    prepared = delivery.publisher.prepare_source(unknown, sources=delivery.sources)
    delivery.publisher.publish(prepared, fence=case.h.lease.fence)
    assert all(item.state.value == "unknown" for item in case.h.resolved().attempts)
    assert case.h.resolved().obligations == batch.attempts.result.obligations
    assert case.store.restore(case.scope).checkpoint.state == previous.checkpoint.state


def test_expiry_between_first_check_and_venue_callback_consumes_send_without_effect(
    attempt_case, monkeypatch
):
    case, source, _descriptor, _publisher, batch, delivery, venue = activated_delivery(attempt_case)
    attempt_id = source.envelopes[0].event.attempt_id
    before = venue.read()
    original_at = case.h.clock.instant
    execute = venue.execute

    def late(command, **kwargs):
        case.h.clock.instant = source.source.valid_until
        return execute(command, **kwargs)

    monkeypatch.setattr(venue, "execute", late)
    receipt = delivery.deliver(batch, source=source, attempt_id=attempt_id)
    assert receipt.acknowledgment.disposition == "rejected"
    rejected = venue.read()
    assert rejected.state.sequence == before.state.sequence + 1
    assert rejected.state.accounting == before.state.accounting
    assert rejected.state.facts == before.state.facts
    case.h.clock.instant = original_at
    with pytest.raises(ValueError, match="ALREADY_CONSUMED"):
        delivery.deliver(batch, source=source, attempt_id=attempt_id)
    assert all(item.state.value == "in_flight" for item in case.h.resolved().attempts)
