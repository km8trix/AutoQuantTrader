from __future__ import annotations

import hashlib
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, cast

import pytest

from packages.domain.advanced_risk import AdvancedRiskObservationCompleteness
from packages.domain.advanced_risk_policy import (
    MODERATE_ADVANCED_RISK_INSTRUMENTS,
    AdvancedRiskDisposition,
    AdvancedRiskEvaluationMode,
    ModerateAdvancedRiskRuleId,
    advanced_risk_policy_source_set_sha256,
    evaluate_moderate_advanced_risk,
)
from packages.domain.advanced_risk_sources import (
    PROPOSED_BATCH_BUY_EXPOSURE_AUTHORITY_SHA256,
    AdvancedRiskExposureDerivation,
    AdvancedRiskExposureEvidence,
    AdvancedRiskExposureSourceConflict,
    AdvancedRiskExposureSourceError,
    ProposedBatchBuyExposure,
    ProposedBatchBuyExposureSet,
    derive_advanced_risk_exposure_evidence,
    proposed_batch_buy_exposure_from_phase2,
)
from packages.domain.batch_risk import (
    ActiveCapacityAuthorization,
    ActiveCapacityReservation,
    ActiveCapacityReservationState,
    ActiveCapacityUniverse,
    VersionedBatchRiskSnapshot,
)
from packages.domain.models import MarketEvent, PortfolioSnapshot, Side
from packages.domain.portfolio import portfolio_snapshot
from tests.unit.test_batch_risk import AS_OF, limits, make_batch, snapshot

OBSERVED_AT = AS_OF + timedelta(seconds=10)
RECORDED_AT = OBSERVED_AT + timedelta(milliseconds=1)
ACCOUNT_ID = "batch-risk-account"
SYMBOL_BY_ID = {
    "US-ETF-DIA": "DIA",
    "US-ETF-IWM": "IWM",
    "US-ETF-QQQ": "QQQ",
    "US-ETF-SPY": "SPY",
}


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def clone_frozen[T](value: T, **changes: object) -> T:
    cloned = object.__new__(type(value))
    for definition in fields(cast(Any, value)):
        object.__setattr__(
            cloned,
            definition.name,
            changes.get(definition.name, getattr(value, definition.name)),
        )
    return cloned


def market(
    instrument_id: str,
    *,
    price: Decimal = Decimal("100"),
) -> MarketEvent:
    return MarketEvent(
        event_id=f"advanced-risk-price-{instrument_id}",
        instrument_id=instrument_id,
        symbol=SYMBOL_BY_ID[instrument_id],
        event_time=AS_OF - timedelta(minutes=1),
        available_at=AS_OF,
        close_price=price,
        source="advanced-risk-source-test-tape-v1",
        source_sequence=MODERATE_ADVANCED_RISK_INSTRUMENTS.index(instrument_id) + 1,
        observation_id=f"advanced-risk-price-observation-{instrument_id}",
    )


def portfolio(
    *,
    positions: dict[str, Decimal] | None = None,
    instruments: tuple[str, ...] = MODERATE_ADVANCED_RISK_INSTRUMENTS,
    prices: dict[str, Decimal] | None = None,
) -> PortfolioSnapshot:
    positions = {} if positions is None else positions
    prices = {} if prices is None else prices
    return portfolio_snapshot(
        as_of=AS_OF,
        current_positions={
            instrument_id: (SYMBOL_BY_ID[instrument_id], quantity)
            for instrument_id, quantity in positions.items()
        },
        price_events=tuple(
            market(instrument_id, price=prices.get(instrument_id, Decimal("100")))
            for instrument_id in instruments
        ),
    )


def risk_snapshot(
    *,
    positions: dict[str, Decimal] | None = None,
    prices: dict[str, Decimal] | None = None,
    equity: Decimal = Decimal("1000"),
    instruments: tuple[str, ...] = MODERATE_ADVANCED_RISK_INSTRUMENTS,
) -> VersionedBatchRiskSnapshot:
    retained = portfolio(
        positions=positions,
        prices=prices,
        instruments=instruments,
    )
    current_gross = sum(
        (
            quantity * (Decimal("100") if prices is None else prices[instrument_id])
            for instrument_id, quantity in (positions or {}).items()
        ),
        Decimal(0),
    )
    return snapshot(
        retained,
        account_id=ACCOUNT_ID,
        available_cash=equity - current_gross,
    )


def authorization(
    label: str,
    instrument_id: str,
    *,
    side: Side = Side.BUY,
    remaining_buy_exposure: Decimal = Decimal("50"),
    remaining_sell_quantity: Decimal = Decimal("0"),
) -> ActiveCapacityAuthorization:
    if side is Side.SELL:
        reserved_buy_exposure = Decimal(0)
        remaining_buy_exposure = Decimal(0)
        reserved_cash = Decimal(0)
        remaining_cash = Decimal(0)
        reserved_sell_quantity = remaining_sell_quantity
    else:
        reserved_buy_exposure = remaining_buy_exposure
        reserved_cash = remaining_buy_exposure
        remaining_cash = remaining_buy_exposure
        reserved_sell_quantity = Decimal(0)
        remaining_sell_quantity = Decimal(0)
    return ActiveCapacityAuthorization(
        authorization_id=f"authorization-{label}",
        authorization_sha256=digest(f"authorization-{label}"),
        intent_id=f"intent-{label}",
        instrument_id=instrument_id,
        side=side,
        reserved_cash=reserved_cash,
        reserved_sell_quantity=reserved_sell_quantity,
        reserved_buy_exposure=reserved_buy_exposure,
        remaining_cash=remaining_cash,
        remaining_sell_quantity=remaining_sell_quantity,
        remaining_buy_exposure=remaining_buy_exposure,
    )


def reservation(
    label: str,
    state: ActiveCapacityReservationState,
    *authorizations: ActiveCapacityAuthorization,
) -> ActiveCapacityReservation:
    ordered = tuple(
        sorted(
            authorizations,
            key=lambda item: (item.instrument_id, item.authorization_id),
        )
    )
    return ActiveCapacityReservation(
        reservation_id=f"reservation-{label}",
        reservation_sha256=digest(f"reservation-{label}"),
        projection_sha256=digest(f"projection-{label}"),
        provenance_sha256=digest(f"provenance-{label}"),
        currency="USD",
        state=state,
        authorizations=ordered,
    )


def universe(
    *reservations: ActiveCapacityReservation,
) -> ActiveCapacityUniverse:
    return ActiveCapacityUniverse(
        account_id=ACCOUNT_ID,
        reservations=tuple(sorted(reservations, key=lambda item: item.reservation_id)),
    )


def proposed(
    retained: VersionedBatchRiskSnapshot,
    *members: ProposedBatchBuyExposure,
) -> ProposedBatchBuyExposureSet:
    return ProposedBatchBuyExposureSet(
        intent_batch_id="proposed-batch-0001",
        intent_batch_sha256=digest("proposed-batch"),
        snapshot_sha256=retained.semantic_sha256,
        exposure_authority_sha256=PROPOSED_BATCH_BUY_EXPOSURE_AUTHORITY_SHA256,
        members=tuple(sorted(members, key=lambda item: (item.instrument_id, item.intent_id))),
    )


def member(
    label: str,
    instrument_id: str,
    exposure: Decimal,
) -> ProposedBatchBuyExposure:
    return ProposedBatchBuyExposure(
        intent_id=f"intent-{label}",
        intent_sha256=digest(f"intent-{label}"),
        instrument_id=instrument_id,
        exposure=exposure,
    )


def evidence(
    retained: VersionedBatchRiskSnapshot,
    active: ActiveCapacityUniverse,
    *,
    proposed_exposure: ProposedBatchBuyExposureSet | None = None,
) -> AdvancedRiskExposureEvidence:
    return derive_advanced_risk_exposure_evidence(
        snapshot=retained,
        active_capacity=active,
        proposed=proposed_exposure,
        fence_token=7,
        fence_sha256=digest("coordinator-fence-7"),
        observed_at=OBSERVED_AT,
        recorded_at=RECORDED_AT,
    )


def derivation(
    result: AdvancedRiskExposureEvidence,
    rule_id: ModerateAdvancedRiskRuleId,
    subject_id: str,
) -> AdvancedRiskExposureDerivation:
    return next(
        item
        for item in result.derivations
        if item.rule_id is rule_id and item.subject_id == subject_id
    )


def test_phase2_projection_uses_the_exact_buffered_reservation_terms() -> None:
    retained = risk_snapshot()
    target, batch = make_batch(
        retained.portfolio_snapshot,
        desired={"US-ETF-SPY": Decimal("2")},
        target_id="advanced-risk-proposed-target",
    )

    projection = proposed_batch_buy_exposure_from_phase2(
        batch=batch,
        target=target,
        snapshot=retained,
        limits=limits(),
        evaluated_at=OBSERVED_AT,
    )

    assert projection.intent_batch_id == batch.intent_batch_id
    assert projection.intent_batch_sha256 == batch.semantic_sha256
    assert projection.snapshot_sha256 == retained.semantic_sha256
    assert projection.exposure_authority_sha256 == (PROPOSED_BATCH_BUY_EXPOSURE_AUTHORITY_SHA256)
    assert len(projection.members) == 1
    assert projection.members[0].instrument_id == "US-ETF-SPY"
    assert projection.members[0].exposure == Decimal("201")


def test_current_active_frozen_and_proposed_buys_are_included_once_and_sells_ignored() -> None:
    retained = risk_snapshot(
        positions={"US-ETF-SPY": Decimal("1")},
        equity=Decimal("1000"),
    )
    active = universe(
        reservation(
            "active",
            ActiveCapacityReservationState.ACTIVE,
            authorization("iwm-buy", "US-ETF-IWM", remaining_buy_exposure=Decimal("50")),
            authorization(
                "qqq-sell",
                "US-ETF-QQQ",
                side=Side.SELL,
                remaining_sell_quantity=Decimal("8"),
            ),
        ),
        reservation(
            "frozen",
            ActiveCapacityReservationState.FROZEN,
            authorization(
                "spy-frozen-buy",
                "US-ETF-SPY",
                remaining_buy_exposure=Decimal("200"),
            ),
        ),
    )
    proposed_exposure = proposed(
        retained,
        member("spy-proposed", "US-ETF-SPY", Decimal("50")),
    )

    result = evidence(retained, active, proposed_exposure=proposed_exposure)
    spy = derivation(
        result,
        ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
        "US-ETF-SPY",
    )
    iwm = derivation(
        result,
        ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
        "US-ETF-IWM",
    )
    qqq = derivation(
        result,
        ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
        "US-ETF-QQQ",
    )
    gross = derivation(
        result,
        ModerateAdvancedRiskRuleId.GROSS_LEVERAGE_MULTIPLE,
        ACCOUNT_ID,
    )
    abs_net = derivation(
        result,
        ModerateAdvancedRiskRuleId.ABS_NET_LEVERAGE_MULTIPLE,
        ACCOUNT_ID,
    )

    assert spy.current_component == Decimal("100")
    assert spy.active_buy_component == Decimal("200")
    assert spy.proposed_buy_component == Decimal("50")
    assert spy.numerator == Decimal("350")
    assert spy.denominator == Decimal("1000")
    assert spy.value == Decimal("0.35")
    assert iwm.value == Decimal("0.05")
    assert qqq.value == Decimal("0")
    assert gross.numerator == Decimal("400")
    assert gross.value == Decimal("0.4")
    assert abs_net.numerator == gross.numerator
    assert abs_net.value == gross.value
    assert len(result.observations) == 7
    assert result.watermark.proposed_exposure_sha256 == proposed_exposure.semantic_sha256


def test_exact_concentration_equality_passes_pretrade() -> None:
    retained = risk_snapshot(
        positions={"US-ETF-SPY": Decimal("1")},
        equity=Decimal("1000"),
    )
    result = evidence(
        retained,
        universe(
            reservation(
                "pending",
                ActiveCapacityReservationState.ACTIVE,
                authorization(
                    "spy-pending",
                    "US-ETF-SPY",
                    remaining_buy_exposure=Decimal("250"),
                ),
            )
        ),
    )
    retained_observation = next(
        item
        for item in result.observations
        if (
            item.rule_id is ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO
            and item.subject_id == "US-ETF-SPY"
        )
    )

    assessment = evaluate_moderate_advanced_risk(
        retained_observation,
        mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        assessed_at=RECORDED_AT,
    )

    assert retained_observation.value == Decimal("0.35")
    assert assessment.disposition is AdvancedRiskDisposition.NONE


def test_subscale_positive_breach_is_projected_upward_not_to_equality() -> None:
    retained = risk_snapshot(equity=Decimal("1000"))
    result = evidence(
        retained,
        universe(
            reservation(
                "pending",
                ActiveCapacityReservationState.PARTIALLY_RELEASED,
                authorization(
                    "spy-subscale",
                    "US-ETF-SPY",
                    remaining_buy_exposure=Decimal("350.00000001"),
                ),
            )
        ),
    )
    spy = derivation(
        result,
        ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
        "US-ETF-SPY",
    )

    assert spy.numerator == Decimal("350.00000001")
    assert spy.denominator == Decimal("1000")
    assert spy.value == Decimal("0.3500000001")
    assessment = evaluate_moderate_advanced_risk(
        next(
            item
            for item in result.observations
            if (
                item.rule_id is ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO
                and item.subject_id == "US-ETF-SPY"
            )
        ),
        mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        assessed_at=RECORDED_AT,
    )
    assert assessment.disposition is AdvancedRiskDisposition.REJECT


def test_proposed_intent_already_in_active_capacity_is_not_double_counted() -> None:
    retained = risk_snapshot()
    active = universe(
        reservation(
            "active",
            ActiveCapacityReservationState.FROZEN,
            authorization(
                "duplicate",
                "US-ETF-SPY",
                remaining_buy_exposure=Decimal("100"),
            ),
        )
    )
    duplicate = proposed(
        retained,
        member("duplicate", "US-ETF-SPY", Decimal("100")),
    )

    with pytest.raises(AdvancedRiskExposureSourceConflict, match="duplicates"):
        evidence(retained, active, proposed_exposure=duplicate)


def test_nonpositive_equity_emits_no_ratio_or_infinity_and_integrity_halts() -> None:
    valid = risk_snapshot(equity=Decimal("1"))
    zero_equity_account = clone_frozen(
        valid.account_projection,
        equity=Decimal("0"),
    )
    retained = clone_frozen(
        valid,
        account_projection=zero_equity_account,
    )
    result = evidence(retained, universe())
    numeric = tuple(
        item
        for item in result.observations
        if item.rule_id is not ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY
    )
    integrity = next(
        item
        for item in result.observations
        if item.rule_id is ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY
    )

    assert "nonpositive_equity" in result.watermark.integrity_reasons
    assert all(
        item.completeness is AdvancedRiskObservationCompleteness.UNAVAILABLE and item.value is None
        for item in numeric
    )
    assert integrity.value == Decimal("1")
    assessment = evaluate_moderate_advanced_risk(
        integrity,
        mode=AdvancedRiskEvaluationMode.RUNTIME,
        assessed_at=RECORDED_AT,
    )
    assert assessment.disposition is AdvancedRiskDisposition.HALT


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    (
        ("negative_position", "negative_position"),
        ("gross_net_mismatch", "gross_abs_net_mismatch"),
    ),
)
def test_corrupt_cash_scope_is_bound_as_integrity_unhealthy(
    mutation: str,
    expected_reason: str,
) -> None:
    retained = risk_snapshot(
        positions={"US-ETF-SPY": Decimal("1")},
        equity=Decimal("1000"),
    )
    if mutation == "negative_position":
        position = retained.account_projection.positions[0]
        corrupted_position = clone_frozen(
            position,
            quantity=Decimal("-1"),
            market_value=Decimal("-100"),
        )
        corrupted_account = clone_frozen(
            retained.account_projection,
            positions=(corrupted_position,),
        )
    else:
        corrupted_account = clone_frozen(
            retained.account_projection,
            net_exposure=Decimal("50"),
        )
    corrupted_snapshot = clone_frozen(
        retained,
        account_projection=corrupted_account,
    )

    result = evidence(corrupted_snapshot, universe())
    integrity = derivation(
        result,
        ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY,
        ACCOUNT_ID,
    )

    assert expected_reason in result.watermark.integrity_reasons
    assert "snapshot_validation_failed" in result.watermark.integrity_reasons
    assert result.watermark.snapshot_validation_complete is False
    assert integrity.value == Decimal("1")
    assert all(
        item.value is None
        for item in result.derivations
        if item.rule_id is not ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY
    )


def test_source_set_binds_snapshot_capacity_batch_and_fence() -> None:
    retained = risk_snapshot()
    active = universe()
    proposed_exposure = proposed(
        retained,
        member("spy-proposed", "US-ETF-SPY", Decimal("10")),
    )
    first = evidence(retained, active, proposed_exposure=proposed_exposure)
    second = derive_advanced_risk_exposure_evidence(
        snapshot=retained,
        active_capacity=active,
        proposed=proposed_exposure,
        fence_token=8,
        fence_sha256=digest("coordinator-fence-8"),
        observed_at=OBSERVED_AT,
        recorded_at=RECORDED_AT,
    )

    assert first.watermark.snapshot_sha256 == retained.semantic_sha256
    assert first.watermark.active_capacity_sha256 == active.semantic_sha256
    assert first.watermark.proposed_batch_sha256 == digest("proposed-batch")
    assert first.watermark.fence_token == 7
    assert first.semantic_sha256 != second.semantic_sha256
    assert {item.source_set_sha256 for item in first.derivations} == {
        first.observations[0].source_set_sha256
    }
    assert first.source_members[0].source_sha256 == first.watermark.semantic_sha256
    assert first.observations[0].source_set_sha256 == (
        advanced_risk_policy_source_set_sha256(
            first.source_members,
            source_count=1,
        )
    )
    for derivation_fact, observation_fact in zip(
        first.derivations,
        first.observations,
        strict=True,
    ):
        assert observation_fact.evidence_sha256 == derivation_fact.semantic_sha256


def test_exact_instrument_coverage_and_proposed_snapshot_binding_are_required() -> None:
    missing_dia = risk_snapshot(
        instruments=(
            "US-ETF-IWM",
            "US-ETF-QQQ",
            "US-ETF-SPY",
        )
    )
    with pytest.raises(AdvancedRiskExposureSourceError, match="exact canonical"):
        evidence(missing_dia, universe())

    retained = risk_snapshot()
    conflicting = ProposedBatchBuyExposureSet(
        intent_batch_id="proposed-batch-0001",
        intent_batch_sha256=digest("proposed-batch"),
        snapshot_sha256=digest("different-snapshot"),
        exposure_authority_sha256=PROPOSED_BATCH_BUY_EXPOSURE_AUTHORITY_SHA256,
        members=(),
    )
    with pytest.raises(AdvancedRiskExposureSourceConflict, match="different risk snapshot"):
        evidence(retained, universe(), proposed_exposure=conflicting)


def test_malformed_proposed_authority_and_non_buy_exposure_fail_closed() -> None:
    retained = risk_snapshot()
    with pytest.raises(AdvancedRiskExposureSourceError, match="derivation authority"):
        ProposedBatchBuyExposureSet(
            intent_batch_id="proposed-batch-0001",
            intent_batch_sha256=digest("proposed-batch"),
            snapshot_sha256=retained.semantic_sha256,
            exposure_authority_sha256=digest("untrusted-authority"),
            members=(),
        )
    with pytest.raises(AdvancedRiskExposureSourceError, match="positive"):
        member("not-buy", "US-ETF-SPY", Decimal("0"))


def test_source_chronology_is_utc_and_causal() -> None:
    retained = risk_snapshot()
    with pytest.raises(AdvancedRiskExposureSourceError, match="inside the regular session"):
        derive_advanced_risk_exposure_evidence(
            snapshot=retained,
            active_capacity=universe(),
            fence_token=7,
            fence_sha256=digest("fence"),
            observed_at=datetime(2026, 7, 15, 21, 0, tzinfo=UTC),
            recorded_at=datetime(2026, 7, 15, 21, 0, tzinfo=UTC),
        )
