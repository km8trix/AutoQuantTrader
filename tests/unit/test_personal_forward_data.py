from dataclasses import FrozenInstanceError, replace
from datetime import UTC, date, datetime, timedelta
from decimal import ROUND_DOWN, Decimal, localcontext

import pytest

from packages.application.personal_forward_data import (
    admit_observation,
    close_frontier,
    quote_admission,
)
from packages.domain.engine_contracts import DailyPrice
from packages.domain.forward_contracts import (
    CaptureReceipt,
    ForwardDataState,
    ForwardObservation,
    ForwardQuote,
    ForwardRequirement,
    ForwardSource,
    ModeledAvailability,
)

AT = datetime(2026, 9, 10, 13, 35, tzinfo=UTC)
DAY = date(2026, 9, 10)
D = Decimal


def source(**changes):
    return replace(
        ForwardSource(
            "captured-quotes",
            "etrade",
            "production",
            "dedicated-simulation-scope",
            "reviewed-source-fixture",
            "allowed",
            "reviewed-rights-fixture",
            "realtime",
            "reviewed-entitlement-fixture",
        ),
        **changes,
    )


def observation(
    identity="obs-1",
    *,
    src=None,
    at=AT,
    sequence=None,
    revision=1,
    parent=None,
    revision_key="quote-1",
    daily=False,
):
    src = src or source()
    receipt = CaptureReceipt(
        identity + "-capture",
        src.semantic_sha256,
        "a" * 64,
        "b" * 64,
        100,
        at - timedelta(milliseconds=20),
        at,
        at + timedelta(milliseconds=20),
        "boot-1",
        980000000,
        1000000000,
        1020000000,
    )
    payload = (
        DailyPrice("spy", "SPY", DAY, D("100"), D("101"), D("101"))
        if daily
        else ForwardQuote(
            "spy",
            "SPY",
            DAY,
            D("99.99"),
            D("100.01"),
            at,
            "USD",
            "realtime",
            at - timedelta(seconds=1),
            at - timedelta(seconds=1),
            "documented_side_times",
        )
    )
    return ForwardObservation(
        identity, src.source_id, payload, receipt, revision_key, revision, parent, sequence
    )


def state(src=None):
    return ForwardDataState((src or source(),), "recorded")


def admit(current, obs):
    return admit_observation(current, obs, admitted_at=obs.known_at)


def requirement(kind="quote", instrument="spy", symbol="SPY"):
    return ForwardRequirement("captured-quotes", instrument, symbol, DAY, kind)


def quote_check(obs=None, src=None, **changes):
    kwargs = {
        "expected": requirement(),
        "environment": "production",
        "account_scope": "dedicated-simulation-scope",
        "evaluated_at": AT + timedelta(milliseconds=100),
        "boot_id": "boot-1",
        "evaluated_monotonic_ns": 1100000000,
    }
    kwargs.update(changes)
    return quote_admission(obs or observation(), src or source(), **kwargs)


def close(current, **changes):
    kwargs = {
        "frontier_id": "decision-1",
        "requirements": (requirement(),),
        "cutoff": AT + timedelta(seconds=10),
        "closed_at": AT + timedelta(seconds=1),
    }
    kwargs.update(changes)
    return close_frontier(current, **kwargs)


def test_records_are_exact_immutable_and_context_independent():
    obs = observation()
    with pytest.raises(FrozenInstanceError):
        obs.observation_id = "changed"
    with pytest.raises(ValueError):
        replace(obs.payload, bid=99.0)
    with pytest.raises(ValueError):
        replace(state(), observations=[])
    expected = obs.semantic_sha256
    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        assert observation().semantic_sha256 == expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("requested_at", AT + timedelta(seconds=1)),
        ("validated_at", AT - timedelta(seconds=1)),
        ("received_at", AT.replace(tzinfo=None)),
        ("requested_monotonic_ns", -1),
        ("validated_monotonic_ns", 2**63),
        ("received_monotonic_ns", 970000000),
        ("byte_count", 0),
        ("byte_count", 32 * 1024 * 1024 + 1),
        ("byte_count", True),
        ("raw_sha256", "unknown"),
    ],
)
def test_capture_rejects_invalid_times_sizes_and_identity(field, value):
    with pytest.raises(ValueError):
        replace(observation().availability, **{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("bid", D("NaN")),
        ("bid", D(0)),
        ("ask", D("-1")),
        ("bid", D("100.02")),
        ("bid", D("0.00000000001")),
        ("symbol", "OTHER"),
        ("source_at", AT.replace(tzinfo=None)),
    ],
)
def test_quote_normalization_rejects_nonfinite_crossed_or_unsupported_values(field, value):
    with pytest.raises(ValueError):
        replace(observation().payload, **{field: value})


def test_quote_freshness_is_strict_and_has_no_fill_or_quantity_authority():
    assert quote_check().eligible
    assert not quote_check(evaluated_at=AT + timedelta(seconds=1)).eligible
    assert not quote_check(evaluated_monotonic_ns=2000000000).eligible
    obs = observation()
    aged = replace(obs, payload=replace(obs.payload, bid_at=AT - timedelta(seconds=4.9)))
    assert "QUOTE_BID_TIME_STALE_OR_FUTURE" in quote_check(aged).reasons
    assert not hasattr(quote_check(), "quantity")
    assert not hasattr(quote_check(), "execution_permit")


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("bid", None, "QUOTE_PRICE_UNAVAILABLE"),
        ("ask", None, "QUOTE_PRICE_UNAVAILABLE"),
        ("bid_at", None, "QUOTE_BID_TIME_UNAVAILABLE"),
        ("ask_at", None, "QUOTE_ASK_TIME_UNAVAILABLE"),
        ("time_basis", "unknown", "QUOTE_SIDE_TIME_BASIS_UNQUALIFIED"),
        ("source_at", AT + timedelta(seconds=1), "QUOTE_SOURCE_TIME_FUTURE"),
        ("source_at", AT + timedelta(milliseconds=1), "QUOTE_SOURCE_TIME_AFTER_RECEIPT"),
        ("currency", None, "QUOTE_CURRENCY_UNQUALIFIED"),
        ("currency", "EUR", "QUOTE_CURRENCY_UNQUALIFIED"),
        ("delay_status", "unknown", "QUOTE_DELAY_UNQUALIFIED"),
        ("delay_status", "delayed", "QUOTE_DELAY_UNQUALIFIED"),
    ],
)
def test_unknown_quote_values_do_not_gain_qualification(field, value, reason):
    obs = observation()
    result = quote_check(replace(obs, payload=replace(obs.payload, **{field: value})))
    assert not result.eligible and reason in result.reasons


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"identity_reference": None}, "SOURCE_IDENTITY_UNKNOWN"),
        ({"rights_status": "unknown"}, "SOURCE_RIGHTS_UNAVAILABLE"),
        ({"rights_status": "denied"}, "SOURCE_RIGHTS_UNAVAILABLE"),
        ({"rights_reference": None}, "SOURCE_RIGHTS_UNAVAILABLE"),
        ({"entitlement_status": "unknown"}, "QUOTE_ENTITLEMENT_UNAVAILABLE"),
        ({"entitlement_reference": None}, "QUOTE_ENTITLEMENT_UNAVAILABLE"),
        ({"account_scope": None}, "QUOTE_SCOPE_MISMATCH"),
        ({"environment": "sandbox"}, "QUOTE_NOT_PRODUCTION_OBSERVATION"),
    ],
)
def test_source_declarations_are_explicit_and_bound(changes, reason):
    src = source(**changes)
    result = quote_check(observation(src=src), src)
    assert not result.eligible and reason in result.reasons


def test_quote_clock_and_exact_scope_changes_block():
    for changes in (
        {"boot_id": "boot-2"},
        {"evaluated_monotonic_ns": 1010000000},
        {"evaluated_at": AT},
        {"expected": requirement(instrument="iwm", symbol="IWM")},
        {"account_scope": "other"},
        {"environment": "sandbox"},
    ):
        assert not quote_check(**changes).eligible
    with pytest.raises(ValueError):
        quote_check(evaluated_monotonic_ns=True)
    assert (
        "CAPTURE_SOURCE_BINDING_MISMATCH"
        in quote_check(src=source(identity_reference="new")).reasons
    )


@pytest.mark.parametrize("side", ["bid_at", "ask_at"])
def test_fresh_wrapper_never_refreshes_stale_or_unknown_side(side):
    obs = observation()
    for at in (None, AT - timedelta(seconds=5), AT + timedelta(milliseconds=1)):
        changed = replace(obs, payload=replace(obs.payload, **{side: at}))
        assert not quote_check(changed).eligible
    # Wrapper absence has no inferred timestamp; independently documented sides suffice.
    assert quote_check(replace(obs, payload=replace(obs.payload, source_at=None))).eligible


def test_modeled_availability_never_becomes_recorded_capture():
    synthetic = source(provider="fixture", environment="synthetic")
    obs = replace(
        observation(src=synthetic), availability=ModeledAvailability(AT, "synthetic-clock/1")
    )
    modeled = ForwardDataState((synthetic,), "modeled")
    assert admit(modeled, obs).disposition == "accepted"
    assert not quote_check(obs, synthetic).eligible
    assert admit(state(), replace(obs, source_id=source().source_id)).disposition == "rejected"
    assert admit(modeled, observation(src=synthetic)).disposition == "rejected"
    with pytest.raises(ValueError):
        ForwardDataState((synthetic,), "recorded")


def test_duplicate_conflict_and_raw_capture_binding_are_exact():
    first = observation()
    applied = admit(state(), first)
    assert applied.disposition == "accepted"
    assert admit(applied.state, first).disposition == "duplicate"
    conflict = replace(first, payload=replace(first.payload, ask=D("100.02")))
    rejected = admit(applied.state, conflict)
    assert rejected.state == applied.state and rejected.reasons == ("OBSERVATION_ID_CONFLICT",)
    second = observation("obs-2", revision_key="quote-2")
    second = replace(
        second,
        availability=replace(
            second.availability, capture_id=first.availability.capture_id, raw_sha256="c" * 64
        ),
    )
    assert "CAPTURE_ID_CONFLICT" in admit(applied.state, second).reasons
    assert admit_observation(state(), first, admitted_at=AT).reasons == (
        "OBSERVATION_NOT_YET_AVAILABLE",
    )


def test_missing_predecessor_recovers_without_rewriting_receipt_or_closed_watermark():
    original = observation("old", daily=True, at=AT + timedelta(seconds=1))
    revision = observation("new", daily=True, revision=2, parent="old", at=AT)
    pending = admit(state(), revision)
    assert pending.disposition == "pending" and pending.reasons == ("REVISION_GAP",)
    assert close(pending.state, requirements=(requirement("daily"),)).disposition == "pending"
    recovered = admit(pending.state, original)
    done = close(
        recovered.state, requirements=(requirement("daily"),), closed_at=AT + timedelta(seconds=2)
    )
    assert done.frontier.status == "complete"
    assert done.frontier.selected[0][1] == "new"
    assert revision.known_at < original.known_at
    assert dict((o.observation_id, o) for o in recovered.state.observations)["new"] == revision


def test_fork_or_cross_instrument_predecessor_never_silently_replaces_head():
    first = observation("old", daily=True)
    revision = observation("new", daily=True, revision=2, parent="old")
    current = admit(admit(state(), first).state, revision).state
    assert "REVISION_FORK" in admit(current, replace(revision, observation_id="fork")).reasons
    cross = replace(
        revision,
        observation_id="cross",
        revision_key="other",
        payload=replace(revision.payload, instrument_id="iwm", symbol="IWM"),
    )
    assert "REVISION_CHAIN_CONFLICT" in admit(current, cross).reasons
    with pytest.raises(ValueError):
        replace(state(), observations=(first, cross))


def test_source_sequences_need_declared_scope_and_recover_gaps_without_range_allocation():
    with pytest.raises(ValueError):
        source(sequence_scope="feed")
    assert "SOURCE_SEQUENCE_SCOPE_UNQUALIFIED" in admit(state(), observation(sequence=1)).reasons
    src = source(sequence_scope="feed", sequence_start=10, sequence_reference="documented-sequence")
    later = observation("later", src=src, sequence=11, revision_key="later")
    result = admit(state(src), later)
    assert result.disposition == "pending" and "SOURCE_SEQUENCE_GAP" in result.reasons
    first = observation(
        "first", src=src, sequence=10, revision_key="first", at=AT - timedelta(seconds=1)
    )
    recovered = admit(result.state, first)
    assert close(recovered.state).frontier.status == "complete"
    repeated = observation("other", src=src, sequence=11, revision_key="other")
    assert "SOURCE_SEQUENCE_CONFLICT" in admit(recovered.state, repeated).reasons
    huge = observation("huge", src=src, sequence=2**62, revision_key="huge")
    assert "SOURCE_SEQUENCE_GAP" in admit(recovered.state, huge).reasons


def test_unknown_rights_retains_receipt_but_cannot_close_complete_data():
    src = source(rights_status="unknown", rights_reference=None)
    pending = admit(state(src), observation(src=src))
    assert pending.disposition == "pending" and len(pending.state.observations) == 1
    assert close(pending.state).disposition == "pending"


def test_cutoff_equality_skips_even_if_prices_exist_and_no_late_reopening():
    obs = observation()
    before = admit(state(), obs).state
    at_cutoff = close(before, closed_at=AT + timedelta(seconds=10))
    assert at_cutoff.frontier.status == "skipped"
    assert at_cutoff.frontier.reasons == ("DECISION_CUTOFF_REACHED",)
    empty = close(state(), closed_at=AT + timedelta(seconds=10))
    old_head = empty.frontier.semantic_sha256
    late = admit(empty.state, observation("late", at=AT + timedelta(seconds=11))).state
    retry = close(late, closed_at=AT + timedelta(seconds=12))
    assert retry.disposition == "duplicate" and retry.frontier.semantic_sha256 == old_head
    assert retry.frontier.missing and not retry.frontier.selected
    assert "FRONTIER_ID_CONFLICT" in close(late, cutoff=AT + timedelta(seconds=15)).reasons


def test_closed_frontier_ignores_future_observations_and_records_missing_members():
    obs = observation()
    baseline = admit(state(), obs).state
    future = observation("future", at=AT + timedelta(seconds=5), revision_key="future")
    extended = admit(baseline, future).state
    assert close(baseline).frontier == close(extended).frontier
    missing = close(
        baseline,
        requirements=(requirement(), requirement(instrument="iwm", symbol="IWM")),
        closed_at=AT + timedelta(seconds=10),
    ).frontier
    assert len(missing.selected) == 1 and len(missing.missing) == 1
    assert missing.status == "skipped"


def test_complete_watermark_is_data_coverage_not_quote_execution_admission():
    obs = observation()
    result = close(admit(state(), obs).state, closed_at=AT + timedelta(seconds=2))
    assert result.frontier.status == "complete"
    assert not quote_check(
        evaluated_at=AT + timedelta(seconds=2), evaluated_monotonic_ns=3000000000
    ).eligible


def test_ambiguous_daily_roots_and_invalid_requirement_inventory_do_not_close():
    one = observation("one", daily=True, revision_key="first")
    two = observation("two", daily=True, revision_key="second")
    current = admit(admit(state(), one).state, two).state
    assert close(current, requirements=(requirement("daily"),)).reasons == (
        "AMBIGUOUS_DAILY_REVISION_ROOT",
    )
    with pytest.raises(ValueError):
        close(current, requirements=(requirement(), requirement()))
    with pytest.raises(ValueError):
        close(current, requirements=())


def test_equal_receipt_time_does_not_invent_quote_stream_order():
    one = observation("one", revision_key="first")
    two = observation("two", revision_key="second")
    current = admit(admit(state(), one).state, two).state
    assert close(current).reasons == ("AMBIGUOUS_QUOTE_ORDER",)
    src = source(sequence_scope="feed", sequence_start=10, sequence_reference="sequence-proof")
    one = observation("one", src=src, sequence=10, revision_key="first")
    two = observation("two", src=src, sequence=11, revision_key="second")
    current = admit(admit(state(src), one).state, two).state
    assert close(current).frontier.selected == ((requirement().semantic_sha256, "two"),)


def test_new_revision_gap_cannot_be_hidden_by_later_receipt_of_old_revision():
    first = observation("old", daily=True, at=AT + timedelta(seconds=1))
    third = observation("new", daily=True, revision=3, parent="missing", at=AT)
    current = admit(admit(state(), third).state, first).state
    result = close(
        current, requirements=(requirement("daily"),), closed_at=AT + timedelta(seconds=2)
    )
    assert result.disposition == "pending" and result.reasons == ("REVISION_GAP",)


def test_direct_restoration_rejects_forks_receipt_scope_and_selected_row_substitution():
    first = observation("a")
    with pytest.raises(ValueError):
        replace(state(), observations=(first, replace(first, observation_id="b")))
    with pytest.raises(ValueError):
        replace(
            state(),
            observations=(
                replace(first, availability=replace(first.availability, source_sha256="c" * 64)),
            ),
        )
    closed = close(admit(state(), first).state).state
    with pytest.raises(ValueError):
        replace(closed, observations=())
    assert close(closed, frontier_id="other", closed_at=AT).reasons == ("FRONTIER_TIME_REGRESSION",)
