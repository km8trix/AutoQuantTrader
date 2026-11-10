"""Budget actual retained synthetic captures without provider admission or relabeling."""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.domain.forward_capture_contracts import CaptureClockSample
from packages.persistence import continuous_simulation_delivery as delivery
from tests.integration.test_continuous_quote_frontier import case as quote_case  # noqa: F401
from tests.integration.test_personal_forward_capture_journal import capture, journal
from tests.unit.test_personal_forward_capture import Clock, Transport


def test_actual_quote_capture_graphs_share_one_raw_and_metadata_bound(
    quote_case,  # noqa: F811
    monkeypatch,
):
    _checkpoint, closure, store = quote_case
    first = store.resolve(closure)
    original = closure.publications[0]
    at = original.record.receipt.requested_at
    raw = store.artifacts.read(original.record.raw_object)
    second_publication = capture(
        replace(original.record.request, capture_id="quote-budget-second"),
        first.state,
        journal(store.engine),
        store.artifacts,
        clock=Clock(
            samples=tuple(
                CaptureClockSample(
                    at + timedelta(milliseconds=n),
                    1000000000 + n * 1000000,
                    closure.boot_id,
                )
                for n in (400, 500, 600)
            )
        ),
        transport=Transport(raw + b" " * (64 * 1024)),
        head=original.journal_receipt.committed_head,
    )
    second_closure = replace(
        closure,
        closure_id="quote-budget-two-original-captures",
        publications=(original, second_publication),
        selections=(
            replace(
                closure.selections[0],
                observation_id=second_publication.record.observations[0].observation_id,
            ),
        ),
        admitted_at=at + timedelta(milliseconds=700),
        admitted_monotonic_ns=1700000000,
    )
    second = store.resolve(second_closure)
    for value in (first, second):
        store.require_resolved(value)
        assert value.closure.evidence_class == "synthetic_fixture"
    assert original.record.raw_object != second_publication.record.raw_object
    maximum_single = max(
        delivery._check_quote_budget((value,), codec=store.codec) for value in (first, second)
    )
    total = delivery._check_quote_budget((first, second), codec=store.codec)
    assert total > maximum_single
    cap = maximum_single + (total - maximum_single) // 2
    monkeypatch.setattr(delivery, "_MAX_RETAINED_QUOTE_BYTES", cap)
    for value in (first, second):
        assert delivery._check_quote_budget((value,), codec=store.codec) <= cap
    with pytest.raises(ValueError, match="QUOTE_SOURCE_BUDGET_EXCEEDED"):
        delivery._check_quote_budget((first, second), codec=store.codec)
    # This is a pure resource counter. No delivery adapter/provider admission
    # ran, and the actual original captures retain their declared fixture class.
    assert store.resolve(closure).closure == closure
    assert second.closure.evidence_class == "synthetic_fixture"


def test_two_actual_resolutions_deduplicate_original_raw_bytes_and_repeated_identity(
    quote_case,  # noqa: F811
):
    _checkpoint, closure, store = quote_case
    first, second = store.resolve(closure), store.resolve(closure)
    assert first is not second
    for value in (first, second):
        store.require_resolved(value)
        assert value.closure.evidence_class == "synthetic_fixture"
    raw_bytes = closure.publications[0].record.raw_object.byte_count
    single = delivery._check_quote_budget((first,), codec=store.codec)
    second_single = delivery._check_quote_budget((second,), codec=store.codec)
    assert delivery._check_quote_budget((first, first), codec=store.codec) == single
    assert delivery._check_quote_budget((first, second), codec=store.codec) == (
        single + second_single - raw_bytes
    )
