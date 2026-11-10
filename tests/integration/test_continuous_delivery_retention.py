"""Actual C/B/A owners reject an uncommitted independent-venue acknowledgment."""

import pytest

from packages.persistence.continuous_simulation_delivery import SqlContinuousSimulationDelivery
from packages.persistence.stateful_venue import SqlStatefulVenue
from tests.integration.test_continuous_runtime_attempt_sources import attempt_case  # noqa: F401
from tests.integration.test_continuous_simulation_delivery import activated_delivery


def test_uncommitted_venue_ack_is_rejected_and_consumed_across_delivery_adapters(
    attempt_case,  # noqa: F811
    monkeypatch,
):
    case, source, _descriptor, publisher, batch, delivery, venue = activated_delivery(attempt_case)
    attempt_id = source.envelopes[0].event.attempt_id
    before = venue.read()
    pending = []

    def acknowledge_without_append(key, request):
        # Deliberate faulty transport/store acknowledgment: the actual pure
        # venue transition and original one-use verifier ran, but no journal
        # append committed. A prepared journal receipt remains only data.
        prepared = venue.journal.prepare_append(key, request)
        pending.append(prepared)
        return prepared.receipt

    with monkeypatch.context() as patch:
        patch.setattr(venue.journal, "append", acknowledge_without_append)
        with pytest.raises(ValueError, match=r"RETAINED|ACKNOWLEDGMENT|COMMITTED"):
            delivery.deliver(batch, source=source, attempt_id=attempt_id)
    assert len(pending) == 1
    assert venue.journal.read_receipt(venue.key, pending[0].request.command_id) is None
    after = venue.read()
    assert after == before

    second = SqlContinuousSimulationDelivery(publisher=publisher, sources=delivery.sources)
    second_venue = SqlStatefulVenue(
        venue.journal._engine,
        model=second.model,
        artifacts=venue.artifacts,
        codec=venue.codec,
        accounting=venue.accounting,
        verified_sources=second,
    )
    second.bind_venue(second_venue)
    with pytest.raises(ValueError, match="ALREADY_CONSUMED"):
        second.deliver(batch, source=source, attempt_id=attempt_id)
    assert second_venue.read() == before
    assert all(item.state.value == "in_flight" for item in case.h.resolved().attempts)
