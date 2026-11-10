from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest

from packages.domain.advanced_risk import (
    MAX_ADVANCED_RISK_SOURCES,
    AdvancedRiskObservationCompleteness,
)
from packages.domain.advanced_risk_metrics import (
    ADVERSE_MODEL_INPUT_AUTHORITY_SHA256,
    BROKER_OUTCOME_INPUT_AUTHORITY_SHA256,
    BROKER_REQUEST_INPUT_AUTHORITY_SHA256,
    EXECUTION_FILL_INPUT_AUTHORITY_SHA256,
    MINUTE_BAR_INPUT_AUTHORITY_SHA256,
    SCALAR_INPUT_AUTHORITY_SHA256,
    SESSION_EQUITY_INPUT_AUTHORITY_SHA256,
    SIP_QUOTE_INPUT_AUTHORITY_SHA256,
    AdvancedRiskMetricConflict,
    AdvancedRiskMetricError,
    AdvancedRiskMetricFailure,
    AuthenticatedAdverseSlippageEstimate,
    AuthenticatedBrokerRequestPressure,
    AuthenticatedBrokerSubmissionOutcome,
    AuthenticatedExecutionFill,
    AuthenticatedMetricSource,
    AuthenticatedMinuteBar,
    AuthenticatedScalarMetric,
    AuthenticatedSipQuote,
    BrokerSubmissionOutcomeKind,
    SessionEquityPoint,
    produce_broker_reject_observations,
    produce_broker_request_observation,
    produce_metric_failure_observation,
    produce_projected_execution_cost_observation,
    produce_realized_slippage_observation,
    produce_scalar_metric_observation,
    produce_session_risk_observations,
    produce_spread_observation,
    produce_volatility_observation,
)
from packages.domain.advanced_risk_policy import (
    AdvancedRiskDisposition,
    AdvancedRiskEvaluationMode,
    ModerateAdvancedRiskRuleId,
    evaluate_moderate_advanced_risk,
)
from packages.domain.models import Side

ACCOUNT_ID = "paper-account"
INSTRUMENT_ID = "US-ETF-SPY"
NOW = datetime(2026, 7, 28, 15, 0, tzinfo=UTC)
RECORDED = NOW + timedelta(milliseconds=1)
SESSION_OPEN = datetime(2026, 7, 28, 13, 30, tzinfo=UTC)
SESSION_CLOSE = datetime(2026, 7, 28, 20, 0, tzinfo=UTC)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def source(
    label: str,
    authority_sha256: str,
    *,
    effective_at: datetime = NOW - timedelta(seconds=1),
    available_at: datetime | None = None,
) -> AuthenticatedMetricSource:
    return AuthenticatedMetricSource(
        source_id=f"source-{label}",
        source_sha256=digest(f"source-payload-{label}"),
        authority_sha256=authority_sha256,
        effective_at=effective_at,
        available_at=effective_at if available_at is None else available_at,
    )


def session_chain(
    adjusted_values: tuple[Decimal, ...],
    *,
    contribution: Decimal = Decimal(0),
    authority_sha256: str = SESSION_EQUITY_INPUT_AUTHORITY_SHA256,
) -> tuple[SessionEquityPoint, ...]:
    points: list[SessionEquityPoint] = []
    for index, adjusted in enumerate(adjusted_values):
        cumulative = Decimal(0) if index == 0 else contribution
        point = SessionEquityPoint(
            account_id=ACCOUNT_ID,
            session_id="xnys-2026-07-28",
            sequence_number=index,
            previous_point_sha256=(None if index == 0 else points[-1].semantic_sha256),
            equity=adjusted + cumulative,
            cumulative_contributions=cumulative,
            cumulative_withdrawals=Decimal(0),
            source=source(
                f"equity-{index}",
                authority_sha256,
                effective_at=SESSION_OPEN + timedelta(minutes=index * 10),
            ),
        )
        points.append(point)
    return tuple(points)


def minute_bars(
    closes: tuple[Decimal, ...],
    *,
    authority_sha256: str = MINUTE_BAR_INPUT_AUTHORITY_SHA256,
    gap_index: int | None = None,
) -> tuple[AuthenticatedMinuteBar, ...]:
    bars: list[AuthenticatedMinuteBar] = []
    start = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)
    for index, close in enumerate(closes):
        offset = index + (1 if gap_index is not None and index >= gap_index else 0)
        interval_start = start + timedelta(minutes=offset)
        interval_end = interval_start + timedelta(minutes=1)
        bars.append(
            AuthenticatedMinuteBar(
                instrument_id=INSTRUMENT_ID,
                symbol="SPY",
                session_label=date(2026, 7, 28),
                interval_started_at=interval_start,
                interval_ended_at=interval_end,
                close_price=close,
                source_profile_sha256=digest("bar-profile"),
                calendar_sha256=digest("calendar"),
                security_master_sha256=digest("security-master"),
                corporate_action_sha256=digest("corporate-actions"),
                watermark_sha256=digest("bar-watermark"),
                source=source(
                    f"bar-{index}",
                    authority_sha256,
                    effective_at=interval_end,
                ),
            )
        )
    return tuple(bars)


def quote(
    *,
    age: timedelta = timedelta(seconds=4),
    bid: Decimal = Decimal("99.9"),
    ask: Decimal = Decimal("100.1"),
    authority_sha256: str = SIP_QUOTE_INPUT_AUTHORITY_SHA256,
) -> AuthenticatedSipQuote:
    effective = NOW - age
    return AuthenticatedSipQuote(
        instrument_id=INSTRUMENT_ID,
        symbol="SPY",
        bid_price=bid,
        ask_price=ask,
        conditions_valid=True,
        feed_profile_sha256=digest("sip-feed-profile"),
        source=source(
            f"quote-{age}",
            authority_sha256,
            effective_at=effective,
            available_at=effective,
        ),
    )


def fill(
    index: int,
    *,
    effective_at: datetime,
    side: Side = Side.BUY,
    fill_price: Decimal = Decimal("99"),
    arrival_mid: Decimal = Decimal("100"),
    quantity: Decimal = Decimal("1"),
    authority_sha256: str = EXECUTION_FILL_INPUT_AUTHORITY_SHA256,
) -> AuthenticatedExecutionFill:
    return AuthenticatedExecutionFill(
        execution_id=f"execution-{index:03d}",
        attempt_id=f"attempt-{index:03d}",
        instrument_id=INSTRUMENT_ID,
        symbol="SPY",
        side=side,
        quantity=quantity,
        fill_price=fill_price,
        arrival_mid=arrival_mid,
        dispatch_at=effective_at - timedelta(seconds=1),
        arrival_quote_sha256=digest(f"arrival-quote-{index}"),
        source=source(
            f"fill-{index}",
            authority_sha256,
            effective_at=effective_at,
        ),
    )


def outcome(
    sequence: int,
    kind: BrokerSubmissionOutcomeKind,
    *,
    effective_at: datetime,
    authority_sha256: str = BROKER_OUTCOME_INPUT_AUTHORITY_SHA256,
) -> AuthenticatedBrokerSubmissionOutcome:
    return AuthenticatedBrokerSubmissionOutcome(
        attempt_id=f"attempt-{sequence:03d}",
        attempt_sequence=sequence,
        outcome=kind,
        broker_code=(
            "business-reject" if kind is BrokerSubmissionOutcomeKind.BUSINESS_REJECTED else None
        ),
        source=source(
            f"outcome-{sequence}",
            authority_sha256,
            effective_at=effective_at,
        ),
    )


def test_session_loss_and_drawdown_neutralize_external_contributions() -> None:
    points = session_chain(
        (Decimal("1000"), Decimal("1000"), Decimal("980")),
        contribution=Decimal("100"),
    )

    loss, drawdown = produce_session_risk_observations(
        points,
        session_opened_at=SESSION_OPEN,
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert points[1].equity == Decimal("1100")
    assert points[1].adjusted_equity == Decimal("1000")
    assert loss.value == Decimal("0.02")
    assert drawdown.value == Decimal("0.02")
    assert (
        evaluate_moderate_advanced_risk(
            loss,
            mode=AdvancedRiskEvaluationMode.RUNTIME,
            assessed_at=RECORDED,
        ).disposition
        is AdvancedRiskDisposition.NONE
    )


def test_session_high_water_is_gap_free_and_authority_mismatch_is_unavailable() -> None:
    points = session_chain(
        (Decimal("1000"), Decimal("1100"), Decimal("1050")),
        authority_sha256=digest("untrusted-session-authority"),
    )
    _, drawdown = produce_session_risk_observations(
        points,
        session_opened_at=SESSION_OPEN,
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert drawdown.completeness is AdvancedRiskObservationCompleteness.UNAVAILABLE
    with pytest.raises(AdvancedRiskMetricConflict, match="gap"):
        broken = (
            points[0],
            SessionEquityPoint(
                account_id=points[1].account_id,
                session_id=points[1].session_id,
                sequence_number=1,
                previous_point_sha256=digest("wrong-predecessor"),
                equity=points[1].equity,
                cumulative_contributions=points[1].cumulative_contributions,
                cumulative_withdrawals=points[1].cumulative_withdrawals,
                source=points[1].source,
            ),
        )
        produce_session_risk_observations(
            broken,
            session_opened_at=SESSION_OPEN,
            observed_at=NOW,
            recorded_at=RECORDED,
        )


def test_volatility_requires_31_consecutive_version_consistent_rth_bars() -> None:
    bars = minute_bars((*((Decimal("100"),) * 30), Decimal("101.5")))
    retained = produce_volatility_observation(
        account_id=ACCOUNT_ID,
        instrument_id=INSTRUMENT_ID,
        bars=bars,
        session_opened_at=SESSION_OPEN,
        session_closed_at=SESSION_CLOSE,
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert retained.sample_count == 30
    assert retained.value == Decimal("0.015")
    assert (
        evaluate_moderate_advanced_risk(
            retained,
            mode=AdvancedRiskEvaluationMode.RUNTIME,
            assessed_at=RECORDED,
        ).disposition
        is AdvancedRiskDisposition.NONE
    )

    insufficient = produce_volatility_observation(
        account_id=ACCOUNT_ID,
        instrument_id=INSTRUMENT_ID,
        bars=bars[:-1],
        session_opened_at=SESSION_OPEN,
        session_closed_at=SESSION_CLOSE,
        observed_at=NOW,
        recorded_at=RECORDED,
    )
    unavailable = produce_volatility_observation(
        account_id=ACCOUNT_ID,
        instrument_id=INSTRUMENT_ID,
        bars=minute_bars(
            (*((Decimal("100"),) * 30), Decimal("101.5")),
            gap_index=10,
        ),
        session_opened_at=SESSION_OPEN,
        session_closed_at=SESSION_CLOSE,
        observed_at=NOW,
        recorded_at=RECORDED,
    )
    assert insufficient.completeness is AdvancedRiskObservationCompleteness.INSUFFICIENT
    assert unavailable.completeness is AdvancedRiskObservationCompleteness.UNAVAILABLE


def test_spread_and_projected_cost_preserve_exact_equality_boundaries() -> None:
    retained_quote = quote()
    spread = produce_spread_observation(
        account_id=ACCOUNT_ID,
        quote=retained_quote,
        session_opened_at=SESSION_OPEN,
        session_closed_at=SESSION_CLOSE,
        observed_at=NOW,
        recorded_at=RECORDED,
    )
    estimate = AuthenticatedAdverseSlippageEstimate(
        instrument_id=INSTRUMENT_ID,
        symbol="SPY",
        adverse_bps=Decimal("15"),
        model_id="paper-adverse-model",
        model_version="1",
        model_sha256=digest("paper-adverse-model-v1"),
        excludes_spread=True,
        source=source(
            "adverse-model",
            ADVERSE_MODEL_INPUT_AUTHORITY_SHA256,
            effective_at=NOW - timedelta(seconds=1),
        ),
    )
    cost = produce_projected_execution_cost_observation(
        account_id=ACCOUNT_ID,
        quote=retained_quote,
        estimate=estimate,
        session_opened_at=SESSION_OPEN,
        session_closed_at=SESSION_CLOSE,
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert spread.value == Decimal("20")
    assert cost.value == Decimal("25")
    for observation in (spread, cost):
        assert (
            evaluate_moderate_advanced_risk(
                observation,
                mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
                assessed_at=RECORDED,
            ).disposition
            is AdvancedRiskDisposition.NONE
        )


def test_sip_freshness_is_strict_and_equality_is_unavailable() -> None:
    retained = produce_spread_observation(
        account_id=ACCOUNT_ID,
        quote=quote(age=timedelta(seconds=5)),
        session_opened_at=SESSION_OPEN,
        session_closed_at=SESSION_CLOSE,
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert retained.completeness is AdvancedRiskObservationCompleteness.UNAVAILABLE
    assert retained.value is None


def test_realized_slippage_is_side_aware_weighted_and_can_be_favorable() -> None:
    fills = tuple(
        fill(
            index,
            effective_at=NOW - timedelta(minutes=20) + timedelta(seconds=index),
            side=Side.BUY if index % 2 == 0 else Side.SELL,
            fill_price=Decimal("99") if index % 2 == 0 else Decimal("101"),
            quantity=Decimal(index + 1),
        )
        for index in range(20)
    )
    retained = produce_realized_slippage_observation(
        account_id=ACCOUNT_ID,
        fills=fills,
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert retained.sample_count == 20
    assert retained.value == Decimal("-100")
    assert (
        evaluate_moderate_advanced_risk(
            retained,
            mode=AdvancedRiskEvaluationMode.RUNTIME,
            assessed_at=RECORDED,
        ).disposition
        is AdvancedRiskDisposition.NONE
    )


def test_realized_slippage_window_is_open_left_and_requires_exactly_20() -> None:
    cutoff = NOW - timedelta(minutes=30)
    fills = tuple(
        fill(
            index,
            effective_at=(cutoff if index == 0 else cutoff + timedelta(seconds=index)),
        )
        for index in range(20)
    )

    retained = produce_realized_slippage_observation(
        account_id=ACCOUNT_ID,
        fills=fills,
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert retained.sample_count == 19
    assert retained.completeness is AdvancedRiskObservationCompleteness.INSUFFICIENT


def test_reject_rate_requires_counts_and_consecutive_suffix_does_not_bridge_unknown() -> None:
    kinds = (
        *((BrokerSubmissionOutcomeKind.ACCEPTED,) * 7),
        *((BrokerSubmissionOutcomeKind.BUSINESS_REJECTED,) * 3),
    )
    outcomes = tuple(
        outcome(
            index + 1,
            kind,
            effective_at=NOW - timedelta(minutes=9) + timedelta(seconds=index),
        )
        for index, kind in enumerate(kinds)
    )
    rate, consecutive = produce_broker_reject_observations(
        account_id=ACCOUNT_ID,
        outcomes=outcomes,
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert rate.value == Decimal("0.3")
    assert rate.sample_count == 10
    assert rate.qualifying_count == 3
    assert consecutive.value == Decimal("3")
    assert (
        evaluate_moderate_advanced_risk(
            rate,
            mode=AdvancedRiskEvaluationMode.RUNTIME,
            assessed_at=RECORDED,
        ).disposition
        is AdvancedRiskDisposition.PAUSE
    )

    unresolved = (
        *outcomes,
        outcome(
            11,
            BrokerSubmissionOutcomeKind.UNRESOLVED,
            effective_at=NOW - timedelta(seconds=1),
        ),
    )
    _, unresolved_suffix = produce_broker_reject_observations(
        account_id=ACCOUNT_ID,
        outcomes=unresolved,
        observed_at=NOW,
        recorded_at=RECORDED,
    )
    assert unresolved_suffix.completeness is (AdvancedRiskObservationCompleteness.UNAVAILABLE)


def test_reject_rate_exact_halt_equality_remains_pause() -> None:
    kinds = (
        *((BrokerSubmissionOutcomeKind.ACCEPTED,) * 15),
        *((BrokerSubmissionOutcomeKind.BUSINESS_REJECTED,) * 5),
    )
    outcomes = tuple(
        outcome(
            index + 1,
            kind,
            effective_at=NOW - timedelta(minutes=9) + timedelta(seconds=index),
        )
        for index, kind in enumerate(kinds)
    )
    rate, _ = produce_broker_reject_observations(
        account_id=ACCOUNT_ID,
        outcomes=outcomes,
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert rate.value == Decimal("0.25")
    assert (
        evaluate_moderate_advanced_risk(
            rate,
            mode=AdvancedRiskEvaluationMode.RUNTIME,
            assessed_at=RECORDED,
        ).disposition
        is AdvancedRiskDisposition.PAUSE
    )


def test_reject_window_excludes_exact_old_boundary() -> None:
    cutoff = NOW - timedelta(minutes=10)
    outcomes = tuple(
        outcome(
            index + 1,
            BrokerSubmissionOutcomeKind.ACCEPTED,
            effective_at=(cutoff if index == 0 else cutoff + timedelta(seconds=index)),
        )
        for index in range(10)
    )
    rate, _ = produce_broker_reject_observations(
        account_id=ACCOUNT_ID,
        outcomes=outcomes,
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert rate.sample_count == 9
    assert rate.completeness is AdvancedRiskObservationCompleteness.INSUFFICIENT


def test_broker_request_projection_adds_proposed_once_and_equality_passes() -> None:
    pressure = AuthenticatedBrokerRequestPressure(
        account_id=ACCOUNT_ID,
        current_request_count=159,
        proposed_new_entry_count=1,
        window_started_at=NOW - timedelta(minutes=1),
        window_ended_at=NOW,
        source=source(
            "request-pressure",
            BROKER_REQUEST_INPUT_AUTHORITY_SHA256,
            effective_at=NOW,
        ),
    )
    retained = produce_broker_request_observation(
        pressure,
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert retained.value == Decimal("160")
    assert (
        evaluate_moderate_advanced_risk(
            retained,
            mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
            assessed_at=RECORDED,
        ).disposition
        is AdvancedRiskDisposition.NONE
    )


@pytest.mark.parametrize(
    ("rule_id", "value"),
    (
        (ModerateAdvancedRiskRuleId.CLOCK_DRIFT_MILLISECONDS, Decimal("1000")),
        (ModerateAdvancedRiskRuleId.MARKET_DATA_AGE_SECONDS, Decimal("15")),
        (ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY, Decimal("0")),
        (
            ModerateAdvancedRiskRuleId.UNKNOWN_SUBMISSION_DURATION_SECONDS,
            Decimal("60"),
        ),
        (
            ModerateAdvancedRiskRuleId.RECONCILIATION_DURATION_SECONDS,
            Decimal("120"),
        ),
    ),
)
def test_scalar_health_unknown_and_reconciliation_boundaries(
    rule_id: ModerateAdvancedRiskRuleId,
    value: Decimal,
) -> None:
    retained = produce_scalar_metric_observation(
        AuthenticatedScalarMetric(
            account_id=ACCOUNT_ID,
            rule_id=rule_id,
            value=value,
            window_started_at=NOW - timedelta(minutes=5),
            window_ended_at=NOW,
            source=source(
                rule_id.value,
                SCALAR_INPUT_AUTHORITY_SHA256,
                effective_at=NOW,
            ),
        ),
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert retained.value == value
    assert retained.completeness is AdvancedRiskObservationCompleteness.COMPLETE
    assert (
        evaluate_moderate_advanced_risk(
            retained,
            mode=AdvancedRiskEvaluationMode.RUNTIME,
            assessed_at=RECORDED,
        ).disposition
        is AdvancedRiskDisposition.NONE
    )


def test_scalar_authority_mismatch_is_not_upgraded_and_fails_closed() -> None:
    retained = produce_scalar_metric_observation(
        AuthenticatedScalarMetric(
            account_id=ACCOUNT_ID,
            rule_id=ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY,
            value=Decimal("0"),
            window_started_at=NOW - timedelta(minutes=1),
            window_ended_at=NOW,
            source=source(
                "untrusted-health",
                digest("untrusted-health-authority"),
                effective_at=NOW,
            ),
        ),
        observed_at=NOW,
        recorded_at=RECORDED,
    )

    assert retained.completeness is AdvancedRiskObservationCompleteness.UNAVAILABLE
    assert retained.value is None
    assessment = evaluate_moderate_advanced_risk(
        retained,
        mode=AdvancedRiskEvaluationMode.RUNTIME,
        assessed_at=RECORDED,
    )
    assert assessment.disposition is AdvancedRiskDisposition.PAUSE


def test_typed_overflow_retains_bounded_prefix_count_and_full_digest() -> None:
    retained_digests = tuple(
        sorted(digest(f"overflow-source-{index}") for index in range(MAX_ADVANCED_RISK_SOURCES))
    )
    full_digest = digest("full-overflow-source-set")
    retained = produce_metric_failure_observation(
        AdvancedRiskMetricFailure(
            account_id=ACCOUNT_ID,
            rule_id=ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY,
            subject_id=ACCOUNT_ID,
            source_authority_sha256=digest("overflow-authority"),
            completeness=AdvancedRiskObservationCompleteness.OVERFLOWED,
            retained_source_sha256s=retained_digests,
            source_count=MAX_ADVANCED_RISK_SOURCES + 1,
            full_source_set_sha256=full_digest,
            window_started_at=NOW - timedelta(minutes=1),
            window_ended_at=NOW,
            observed_at=NOW,
            recorded_at=RECORDED,
            reason="source membership exceeded its retained bound",
        )
    )

    assert retained.completeness is AdvancedRiskObservationCompleteness.OVERFLOWED
    assert retained.value is None
    assert retained.sample_count == MAX_ADVANCED_RISK_SOURCES + 1
    assert retained.source_set_sha256 == full_digest


def test_scalar_source_at_open_left_boundary_is_rejected() -> None:
    start = NOW - timedelta(minutes=1)
    with pytest.raises(AdvancedRiskMetricConflict, match="open-left"):
        AuthenticatedScalarMetric(
            account_id=ACCOUNT_ID,
            rule_id=ModerateAdvancedRiskRuleId.CLOCK_DRIFT_MILLISECONDS,
            value=Decimal("0"),
            window_started_at=start,
            window_ended_at=NOW,
            source=source(
                "clock-old-boundary",
                SCALAR_INPUT_AUTHORITY_SHA256,
                effective_at=start,
            ),
        )


def test_malformed_quote_and_fill_sources_fail_closed() -> None:
    with pytest.raises(AdvancedRiskMetricError, match="bid"):
        quote(bid=Decimal("101"), ask=Decimal("100"))
    with pytest.raises(AdvancedRiskMetricError, match="chronology"):
        AuthenticatedExecutionFill(
            execution_id="execution-bad",
            attempt_id="attempt-bad",
            instrument_id=INSTRUMENT_ID,
            symbol="SPY",
            side=Side.BUY,
            quantity=Decimal("1"),
            fill_price=Decimal("100"),
            arrival_mid=Decimal("100"),
            dispatch_at=NOW,
            arrival_quote_sha256=digest("arrival"),
            source=source(
                "bad-fill",
                EXECUTION_FILL_INPUT_AUTHORITY_SHA256,
                effective_at=NOW - timedelta(seconds=1),
            ),
        )
