"""Declared provider-shaped synthetic records; no real source qualification."""

from dataclasses import replace
from datetime import timedelta
from decimal import Inexact, Rounded, localcontext

import pytest

from packages.application.runtime_quote_marks import (
    RuntimeQuoteMarkRequest,
    build_runtime_quote_marks,
)
from packages.domain.models import Side
from packages.domain.personal_contracts import VersionPin
from tests.unit.test_personal_forward_data import AT, D, observation, requirement, source

PIN = VersionPin("runtime_quote_marks", "fixture-normalizer/1", "c" * 64)


def request(side=Side.BUY, **changes):
    return replace(
        RuntimeQuoteMarkRequest(observation(), source(), requirement(), side, PIN), **changes
    )


def normalize(requests=None, **changes):
    args = dict(
        environment="production",
        account_scope="dedicated-simulation-scope",
        evaluated_at=AT + timedelta(milliseconds=100),
        boot_id="boot-1",
        evaluated_monotonic_ns=1100000000,
    )
    args.update(changes)
    return build_runtime_quote_marks((request(),) if requests is None else requests, **args)


@pytest.mark.parametrize(
    "side,basis,price,seconds",
    [
        (Side.BUY, "runtime_quote_ask_v1", D("100.01"), 2),
        (Side.SELL, "runtime_quote_bid_v1", D("99.99"), 3),
    ],
)
def test_side_quote_preserves_exact_price_side_time_and_validation_availability(
    side, basis, price, seconds
):
    original = request(side)
    quote = replace(
        original.observation.payload,
        ask_at=AT - timedelta(seconds=2),
        bid_at=AT - timedelta(seconds=3),
    )
    value = replace(original, observation=replace(original.observation, payload=quote))
    (mark,) = normalize((value,))
    assert mark.price == price and mark.basis == basis
    assert mark.economic_at == AT - timedelta(seconds=seconds)
    assert mark.knowledge_at == value.observation.known_at == AT + timedelta(milliseconds=20)
    assert value.observation.availability.received_at == AT
    assert mark.source_sha256 == value.semantic_sha256
    assert mark.quality == "current"
    assert not hasattr(mark, "execution_id") and not hasattr(mark, "live_authorized")


def test_fresh_recheck_and_hostile_decimal_context_do_not_refresh_mark_identity_or_price():
    expected = normalize()
    with localcontext() as context:
        context.prec = 1
        context.traps[Inexact] = context.traps[Rounded] = True
        assert (
            normalize(
                evaluated_at=AT + timedelta(milliseconds=500), evaluated_monotonic_ns=1500000000
            )
            == expected
        )


@pytest.mark.parametrize("field", ["producer", "source", "raw", "side", "revision"])
def test_full_provenance_and_selected_side_change_mark_source_identity(field):
    original = request()
    if field == "producer":
        changed = replace(original, producer=replace(PIN, version="changed/2"))
    elif field == "source":
        src = replace(original.source, identity_reference="different-retained-identity")
        obs = replace(
            original.observation,
            availability=replace(
                original.observation.availability, source_sha256=src.semantic_sha256
            ),
        )
        changed = replace(original, source=src, observation=obs)
    elif field == "raw":
        changed = replace(
            original,
            observation=replace(
                original.observation,
                availability=replace(original.observation.availability, raw_sha256="d" * 64),
            ),
        )
    elif field == "side":
        changed = replace(original, side=Side.SELL)
    else:
        changed = replace(
            original,
            observation=replace(
                original.observation, revision=2, predecessor_id="prior-observation"
            ),
        )
    (first,) = normalize((original,))
    (second,) = normalize((changed,))
    assert first.source_sha256 != second.source_sha256 and first.mark_id != second.mark_id


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"account_scope": "other"}, "QUOTE_SCOPE_MISMATCH"),
        ({"environment": "sandbox"}, "QUOTE_SCOPE_MISMATCH"),
        ({"boot_id": "new-boot"}, "QUOTE_MONOTONIC_BOOT_MISMATCH"),
        (
            {"evaluated_at": AT + timedelta(seconds=1), "evaluated_monotonic_ns": 2000000000},
            "QUOTE_RECEIPT_STALE_OR_FUTURE",
        ),
        ({"evaluated_monotonic_ns": 2000000000}, "QUOTE_MONOTONIC_RECEIPT_STALE_OR_FUTURE"),
        ({"evaluated_at": AT}, "OBSERVATION_NOT_YET_AVAILABLE"),
    ],
)
def test_scope_clock_and_exact_receipt_expiry_fail(changes, reason):
    with pytest.raises(ValueError, match=reason):
        normalize(**changes)


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"rights_status": "unknown"}, "SOURCE_RIGHTS_UNAVAILABLE"),
        ({"identity_reference": None}, "SOURCE_IDENTITY_UNKNOWN"),
        ({"entitlement_status": "unknown"}, "QUOTE_ENTITLEMENT_UNAVAILABLE"),
        ({"environment": "sandbox"}, "QUOTE_NOT_PRODUCTION_OBSERVATION"),
    ],
)
def test_unknown_rights_identity_entitlement_or_sandbox_cannot_normalize(changes, reason):
    src = source(**changes)
    with pytest.raises(ValueError, match=reason):
        normalize((request(source=src, observation=observation(src=src)),))


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"bid_at": AT - timedelta(seconds=5)}, "QUOTE_BID_TIME_STALE_OR_FUTURE"),
        ({"ask_at": AT - timedelta(seconds=5)}, "QUOTE_ASK_TIME_STALE_OR_FUTURE"),
        ({"time_basis": "unknown"}, "QUOTE_SIDE_TIME_BASIS_UNQUALIFIED"),
        ({"delay_status": "delayed"}, "QUOTE_DELAY_UNQUALIFIED"),
        ({"currency": None}, "QUOTE_CURRENCY_UNQUALIFIED"),
    ],
)
def test_quote_fields_and_both_side_ages_remain_mandatory(changes, reason):
    original = request()
    changed = replace(
        original,
        observation=replace(
            original.observation, payload=replace(original.observation.payload, **changes)
        ),
    )
    with pytest.raises(ValueError, match=reason):
        normalize((changed,))


@pytest.mark.parametrize("side", ["buy", "sell", True, None])
def test_side_requires_exact_enum(side):
    with pytest.raises(ValueError):
        request(side)


def test_duplicate_instrument_and_mutable_or_empty_requests_reject():
    for values in ((request(), request(Side.SELL)), (), [request()], (request(),) * 5):
        with pytest.raises(ValueError):
            normalize(values)
    with pytest.raises(ValueError):
        request(producer=None)


def test_multiple_instruments_have_stable_order_and_failure_returns_no_partial_tuple():
    first = request()
    obs = replace(
        first.observation,
        observation_id="qqq-observation",
        payload=replace(first.observation.payload, instrument_id="qqq", symbol="QQQ"),
    )
    second = replace(first, observation=obs, expected=requirement(instrument="qqq", symbol="QQQ"))
    assert normalize((first, second)) == normalize((second, first))
    assert tuple(m.instrument_id for m in normalize((first, second))) == ("qqq", "spy")
    bad = replace(
        second,
        expected=replace(second.expected, session=second.expected.session + timedelta(days=1)),
    )
    with pytest.raises(ValueError, match="QUOTE_SCOPE_MISMATCH"):
        normalize((first, bad))


@pytest.mark.parametrize("basis", ["runtime_quote_ask_v1", "runtime_quote_bid_v1"])
def test_historical_activation_still_rejects_runtime_quote_basis(basis):
    from packages.domain.daily_risk import evaluate_daily_risk
    from packages.domain.engine_contracts import DailyRiskPolicy
    from packages.domain.portfolio import daily_target_to_intents
    from tests.unit.test_daily_risk import evidence
    from tests.unit.test_daily_target_conversion import EXECUTION, OPEN, PIN, account, target

    original = account()
    batch = daily_target_to_intents(target(), original, strategy_pin=PIN)
    snapshot = replace(
        original,
        point=replace(original.point, knowledge_at=OPEN),
        marks=(
            replace(
                original.marks[0],
                basis=basis,
                session=EXECUTION,
                economic_at=OPEN,
                knowledge_at=OPEN,
            ),
        ),
    )
    fact = replace(evidence(snapshot.semantic_sha256), phase="activation", produced_at=OPEN)
    result = evaluate_daily_risk(
        DailyRiskPolicy(),
        snapshot,
        replace(batch, snapshot_sha256=snapshot.semantic_sha256),
        fact,
        OPEN,
    )
    assert not result.approved and "ACTIVATION_REQUIRES_EXECUTION_PRICE" in result.reasons


@pytest.mark.parametrize("basis", ["runtime_quote_ask_v1", "runtime_quote_bid_v1"])
def test_historical_decision_cannot_gain_a_new_quote_mark_basis(basis):
    from packages.domain.daily_risk import evaluate_daily_risk
    from packages.domain.engine_contracts import DailyRiskPolicy
    from packages.domain.portfolio import daily_target_to_intents
    from tests.unit.test_daily_risk import evidence
    from tests.unit.test_daily_target_conversion import NOW, PIN, account, target

    original = account()
    snapshot = replace(original, marks=(replace(original.marks[0], basis=basis),))
    batch = daily_target_to_intents(target(), snapshot, strategy_pin=PIN)
    result = evaluate_daily_risk(
        DailyRiskPolicy(), snapshot, batch, evidence(snapshot.semantic_sha256), NOW
    )
    assert not result.approved
    assert result.reasons == ("RUNTIME_QUOTE_REQUIRES_RUNTIME_EVIDENCE",)
