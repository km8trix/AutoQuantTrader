"""Actual durable dispatch mapping into independent financial-scope captures."""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.domain.stateful_venue_contracts import VenueCommand, VenueReject, VenueRunDue
from packages.persistence.continuous_venue_registration_capture import (
    SqlContinuousVenueRegistrationCapture,
)
from tests.integration.test_continuous_attempt_outcome_sources import outcome_owner
from tests.integration.test_continuous_runtime_attempt_sources import attempt_case  # noqa: F401
from tests.integration.test_continuous_simulation_delivery import activated_delivery


def test_actual_registration_mapping_rejection_and_original_head_guard(
    attempt_case,  # noqa: F811
    monkeypatch,
):
    case, source, _descriptor, _publisher, batch, delivery, venue = activated_delivery(attempt_case)
    outcomes, clock = outcome_owner(case, delivery, venue)
    capture = SqlContinuousVenueRegistrationCapture(outcomes=outcomes)
    for envelope in source.envelopes:
        delivery.deliver(batch, source=source, attempt_id=envelope.event.attempt_id)
    previous, current = case.store.restore(case.scope), case.h.resolved()
    with pytest.raises(ValueError, match="original"):
        capture.capture(capture_id="copied-current", previous=previous, current=replace(current))
    observed = capture.capture(
        capture_id="actual-registered-inventory", previous=previous, current=current
    )
    mappings = observed.pages[0].request.binding.orders
    expected = tuple(
        sorted(
            (item.request.submission for item in source.closure.preparations),
            key=lambda item: item.order_id,
        )
    )
    assert tuple(item.submission for item in mappings) == expected
    assert observed.capture.manifest.scope == case.paired_fixture.scope
    assert observed.capture.manifest.scope != outcomes.scope
    assert {item.order_id for item in observed.capture.observed.orders} == {
        item.order_id for item in expected
    }
    assert all(item.status == "unknown" for item in observed.capture.observed.orders)
    original_venue = venue.read()
    assert observed.pages[0].venue_head == original_venue.head
    case.h.clock.instant = clock.at + timedelta(milliseconds=1)
    order_id = expected[0].order_id
    rejected = venue.execute(
        VenueCommand(
            "independent-order-rejection",
            case.h.clock.instant,
            VenueReject(order_id, "modeled-venue-declined"),
        )
    )
    assert rejected.acknowledgment.disposition == "applied"
    clock.at = case.h.clock.instant
    rejected_capture = capture.capture(
        capture_id="actual-rejected-inventory", previous=previous, current=case.h.resolved()
    )
    assert (
        next(o for o in rejected_capture.capture.observed.orders if o.order_id == order_id).status
        == "rejected"
    )
    assert case.store.restore(case.scope).receipt == previous.receipt
    assert case.h.resolved().obligations == current.obligations
    # A retained SQL journal does not authenticate a subsequently mutated
    # detached financial value. The mapper must run the owner's full guard.
    original_resolve = capture.sources.resolve

    def corrupted_result(value):
        result = original_resolve(value)
        cash = result.capture.observed.cash[0]
        object.__setattr__(cash, "value", cash.value + 1)
        return result

    case.h.clock.instant = clock.at + timedelta(milliseconds=1)
    clock.at = case.h.clock.instant
    with monkeypatch.context() as patch:
        patch.setattr(capture.sources, "resolve", corrupted_result)
        with pytest.raises(ValueError):
            capture.capture(
                capture_id="mutated-detached-cash", previous=previous, current=case.h.resolved()
            )
    # Source capture observes one exact independent head. A later venue commit
    # cannot silently replace the state whose original mappings were discovered.
    case.h.clock.instant = clock.at + timedelta(milliseconds=1)
    clock.at = case.h.clock.instant
    actual_capture = outcomes.capture.capture

    def changed(request, **kwargs):
        venue.execute(VenueCommand("head-moved", case.h.clock.instant, VenueRunDue()))
        return actual_capture(request, **kwargs)

    monkeypatch.setattr(outcomes.capture, "capture", changed)
    with pytest.raises(ValueError, match="HISTORICAL_HEAD_NOT_CURRENT"):
        capture.capture(
            capture_id="changed-original-head", previous=previous, current=case.h.resolved()
        )
    assert case.store.restore(case.scope).receipt == previous.receipt
