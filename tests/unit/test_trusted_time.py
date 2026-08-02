from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal, localcontext
from inspect import signature

import pytest

from packages.domain.trusted_time import (
    TRUSTED_TIME_POLICY,
    TrustedTimeError,
    TrustedTimeEvaluation,
    TrustedTimeHealth,
    TrustedTimeReason,
    TrustedTimeSample,
    TrustedTimeState,
    evaluate_trusted_time,
)

BASE = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)
SECOND_NS = 1_000_000_000


def _sample(
    *,
    second: int,
    offset_microseconds: int = 0,
    sequence: int | None = None,
    source_id: str = "trusted-source-1",
    authority: str = "a" * 64,
    host_id: str = "paper-trader-1",
    epoch_id: str = "monitor-epoch-1",
    evidence: str = "b" * 64,
    started_second: int | None = None,
    started_utc: datetime | None = None,
    uncertainty_milliseconds: Decimal = Decimal("0"),
) -> TrustedTimeSample:
    completed_at = BASE + timedelta(seconds=second)
    selected_started_second = second if started_second is None else started_second
    probe_started_at = (
        BASE + timedelta(seconds=selected_started_second) if started_utc is None else started_utc
    )
    midpoint = probe_started_at + (completed_at - probe_started_at) / 2
    return TrustedTimeSample(
        source_id=source_id,
        source_authority_sha256=authority,
        host_id=host_id,
        monitor_epoch_id=epoch_id,
        sequence=second // 30 + 1 if sequence is None else sequence,
        source_evidence_sha256=evidence,
        probe_started_at_utc=probe_started_at,
        probe_completed_at_utc=completed_at,
        trusted_at_utc=midpoint + timedelta(microseconds=offset_microseconds),
        source_uncertainty_milliseconds=uncertainty_milliseconds,
        probe_started_monotonic_ns=selected_started_second * SECOND_NS,
        probe_completed_monotonic_ns=second * SECOND_NS,
    )


def _evaluate(
    prior: TrustedTimeState | None,
    sample: TrustedTimeSample | None,
    *,
    second: int,
) -> TrustedTimeState:
    return evaluate_trusted_time(
        prior,
        sample,
        evaluated_at_utc=BASE + timedelta(seconds=second),
        evaluated_at_monotonic_ns=second * SECOND_NS,
    ).state


def test_startup_without_a_sample_is_explicitly_blocked() -> None:
    state = _evaluate(None, None, second=0)

    assert state.health is TrustedTimeHealth.BLOCKED
    assert state.sample_health is TrustedTimeHealth.BLOCKED
    assert state.reason is TrustedTimeReason.STARTUP_NO_SAMPLE
    assert state.latest_sample is None
    assert state.clock_recovery_qualified is False
    assert not hasattr(state, "rearm_eligible")


def test_first_sample_must_start_the_epoch_at_sequence_one() -> None:
    state = _evaluate(
        None,
        _sample(second=0, sequence=2),
        second=0,
    )

    assert state.health is TrustedTimeHealth.BLOCKED
    assert state.reason is TrustedTimeReason.SEQUENCE_DISCONTINUITY


@pytest.mark.parametrize("offset_microseconds", [249_999, -249_999, 0])
def test_offset_strictly_below_warning_limit_is_healthy(
    offset_microseconds: int,
) -> None:
    state = _evaluate(
        None,
        _sample(second=0, offset_microseconds=offset_microseconds),
        second=0,
    )

    assert state.sample_health is TrustedTimeHealth.HEALTHY
    assert state.health is TrustedTimeHealth.HEALTHY
    assert state.reason is TrustedTimeReason.STARTUP_QUALIFYING


@pytest.mark.parametrize(
    "offset_microseconds",
    [250_000, -250_000, 1_000_000, -1_000_000],
)
def test_warning_and_hard_limit_equalities_remain_in_warning_band(
    offset_microseconds: int,
) -> None:
    state = _evaluate(
        None,
        _sample(second=0, offset_microseconds=offset_microseconds),
        second=0,
    )

    assert state.sample_health is TrustedTimeHealth.WARNING
    assert state.health is TrustedTimeHealth.WARNING
    assert state.reason is TrustedTimeReason.WARNING_OFFSET
    assert state.hard_failure_latched is False


@pytest.mark.parametrize("offset_microseconds", [1_000_001, -1_000_001])
def test_offset_beyond_hard_limit_blocks_and_latches(
    offset_microseconds: int,
) -> None:
    state = _evaluate(
        None,
        _sample(second=0, offset_microseconds=offset_microseconds),
        second=0,
    )

    assert state.sample_health is TrustedTimeHealth.BLOCKED
    assert state.health is TrustedTimeHealth.BLOCKED
    assert state.reason is TrustedTimeReason.HARD_OFFSET
    assert state.hard_failure_latched is True


@pytest.mark.parametrize(
    ("offset_microseconds", "expected_health"),
    [
        (149_999, TrustedTimeHealth.HEALTHY),
        (-149_999, TrustedTimeHealth.HEALTHY),
        (150_000, TrustedTimeHealth.WARNING),
        (-150_000, TrustedTimeHealth.WARNING),
        (900_000, TrustedTimeHealth.WARNING),
        (-900_000, TrustedTimeHealth.WARNING),
        (900_001, TrustedTimeHealth.BLOCKED),
        (-900_001, TrustedTimeHealth.BLOCKED),
    ],
)
def test_health_uses_absolute_point_offset_plus_uncertainty(
    offset_microseconds: int,
    expected_health: TrustedTimeHealth,
) -> None:
    sample = _sample(
        second=0,
        offset_microseconds=offset_microseconds,
        uncertainty_milliseconds=Decimal("100"),
    )
    state = _evaluate(None, sample, second=0)

    assert sample.offset_magnitude_with_uncertainty_milliseconds == (
        abs(Decimal(offset_microseconds) / Decimal(1_000)) + Decimal("100")
    )
    assert state.sample_health is expected_health


def test_offset_magnitude_and_identity_ignore_low_precision_decimal_context() -> None:
    sample = _sample(
        second=0,
        offset_microseconds=149_999,
        uncertainty_milliseconds=Decimal("99.9999999999"),
    )
    expected_magnitude = Decimal("249.9989999999")
    expected_identity = sample.semantic_sha256

    with localcontext() as context:
        context.prec = 3
        assert sample.offset_milliseconds == Decimal("149.999")
        assert sample.offset_magnitude_with_uncertainty_milliseconds == expected_magnitude
        assert sample.semantic_sha256 == expected_identity
        assert _evaluate(None, sample, second=0).sample_health is TrustedTimeHealth.HEALTHY


def test_gap_free_t0_t30_t60_samples_complete_the_recovery_window() -> None:
    first = _evaluate(None, _sample(second=0), second=0)
    second = _evaluate(first, _sample(second=30), second=30)
    third = _evaluate(second, _sample(second=60), second=60)

    assert first.clock_recovery_qualified is False
    assert second.clock_recovery_qualified is False
    assert third.clock_recovery_qualified is True
    assert third.reason is TrustedTimeReason.WITHIN_LIMIT
    assert third.health is TrustedTimeHealth.HEALTHY


def test_replacement_at_thirty_seconds_preserves_cadence_but_age_equality_is_stale() -> None:
    first_sample = _sample(second=0)
    first = _evaluate(None, first_sample, second=0)

    stale = _evaluate(first, first_sample, second=30)
    replacement = _evaluate(first, _sample(second=30), second=30)

    assert stale.reason is TrustedTimeReason.SAMPLE_STALE
    assert stale.health is TrustedTimeHealth.BLOCKED
    assert replacement.reason is TrustedTimeReason.STARTUP_QUALIFYING
    assert replacement.health is TrustedTimeHealth.HEALTHY
    assert replacement.healthy_since_monotonic_ns == 0


def test_gap_over_thirty_seconds_blocks_and_restarts_the_healthy_chain() -> None:
    first = _evaluate(None, _sample(second=0), second=0)
    after_gap = _evaluate(
        first,
        _sample(second=31, sequence=2),
        second=31,
    )
    next_sample = _evaluate(
        after_gap,
        _sample(second=61, sequence=3),
        second=61,
    )

    assert after_gap.reason is TrustedTimeReason.CADENCE_GAP
    assert after_gap.health is TrustedTimeHealth.BLOCKED
    assert after_gap.healthy_since_monotonic_ns == 31 * SECOND_NS
    assert next_sample.health is TrustedTimeHealth.HEALTHY
    assert next_sample.clock_recovery_qualified is False


def test_warning_resets_recovery_without_latching_hard_failure() -> None:
    first = _evaluate(None, _sample(second=0), second=0)
    second = _evaluate(first, _sample(second=30), second=30)
    warning = _evaluate(
        second,
        _sample(second=60, offset_microseconds=250_000),
        second=60,
    )
    recovered_start = _evaluate(warning, _sample(second=90), second=90)

    assert warning.health is TrustedTimeHealth.WARNING
    assert warning.healthy_since_monotonic_ns is None
    assert warning.hard_failure_latched is False
    assert recovered_start.healthy_since_monotonic_ns == 90 * SECOND_NS
    assert recovered_start.clock_recovery_qualified is False


def test_hard_failure_stays_blocked_after_clock_recovery_qualifies() -> None:
    hard = _evaluate(
        None,
        _sample(second=0, offset_microseconds=1_000_001),
        second=0,
    )
    healthy_start = _evaluate(hard, _sample(second=1, sequence=2), second=1)
    healthy_middle = _evaluate(
        healthy_start,
        _sample(second=31, sequence=3),
        second=31,
    )
    recovered = _evaluate(
        healthy_middle,
        _sample(second=61, sequence=4),
        second=61,
    )

    assert recovered.sample_health is TrustedTimeHealth.HEALTHY
    assert recovered.health is TrustedTimeHealth.BLOCKED
    assert recovered.reason is TrustedTimeReason.HARD_OFFSET_LATCHED
    assert recovered.hard_failure_latched is True
    assert recovered.clock_recovery_qualified is True


@pytest.mark.parametrize(
    ("sample", "reason"),
    [
        (_sample(second=30, sequence=7), TrustedTimeReason.SEQUENCE_DISCONTINUITY),
        (
            _sample(second=30, source_id="trusted-source-2"),
            TrustedTimeReason.IDENTITY_CHANGED,
        ),
        (
            _sample(second=30, host_id="paper-trader-2"),
            TrustedTimeReason.IDENTITY_CHANGED,
        ),
        (
            _sample(second=30, epoch_id="monitor-epoch-2"),
            TrustedTimeReason.IDENTITY_CHANGED,
        ),
    ],
)
def test_sequence_source_host_and_epoch_discontinuities_fail_closed(
    sample: TrustedTimeSample,
    reason: TrustedTimeReason,
) -> None:
    first = _evaluate(None, _sample(second=0), second=0)
    state = _evaluate(first, sample, second=30)

    assert state.health is TrustedTimeHealth.BLOCKED
    assert state.reason is reason
    assert state.clock_recovery_qualified is False


def test_identity_change_never_self_establishes_a_new_recovery_chain() -> None:
    original_sample = _sample(second=0)
    original = _evaluate(None, original_sample, second=0)
    first_rotation = _evaluate(
        original,
        _sample(second=30, source_id="trusted-source-2"),
        second=30,
    )
    second_rotation = _evaluate(
        first_rotation,
        _sample(second=60, sequence=2, source_id="trusted-source-2"),
        second=60,
    )
    third_rotation = _evaluate(
        second_rotation,
        _sample(second=90, sequence=2, source_id="trusted-source-2"),
        second=90,
    )

    for state in (first_rotation, second_rotation, third_rotation):
        assert state.reason is TrustedTimeReason.IDENTITY_CHANGED
        assert state.health is TrustedTimeHealth.BLOCKED
        assert state.latest_sample == original_sample
        assert state.clock_recovery_qualified is False


def test_cross_sample_utc_and_monotonic_regressions_fail_closed() -> None:
    first = _evaluate(None, _sample(second=30, sequence=1), second=30)
    utc_regression = _sample(
        second=30,
        sequence=2,
        started_utc=BASE + timedelta(seconds=29, milliseconds=750),
    )
    monotonic_regression = replace(
        _sample(second=30, sequence=2),
        probe_started_monotonic_ns=29_750_000_000,
    )

    utc_state = _evaluate(first, utc_regression, second=30)
    monotonic_state = _evaluate(first, monotonic_regression, second=30)

    assert utc_state.reason is TrustedTimeReason.UTC_REGRESSION
    assert utc_state.health is TrustedTimeHealth.BLOCKED
    assert monotonic_state.reason is TrustedTimeReason.MONOTONIC_REGRESSION
    assert monotonic_state.health is TrustedTimeHealth.BLOCKED


def test_source_failure_is_explicit_and_resets_the_healthy_chain() -> None:
    first = _evaluate(None, _sample(second=0), second=0)
    unavailable = _evaluate(first, None, second=1)

    assert unavailable.latest_sample == first.latest_sample
    assert unavailable.health is TrustedTimeHealth.BLOCKED
    assert unavailable.reason is TrustedTimeReason.SOURCE_UNAVAILABLE
    assert unavailable.healthy_since_monotonic_ns is None


@pytest.mark.parametrize(
    ("evaluated_at_utc", "evaluated_at_monotonic_ns", "reason"),
    [
        (
            BASE + timedelta(seconds=2),
            0,
            TrustedTimeReason.MONOTONIC_REGRESSION,
        ),
        (
            BASE,
            2 * SECOND_NS,
            TrustedTimeReason.UTC_REGRESSION,
        ),
    ],
)
def test_unavailable_sample_preserves_evaluation_regression_reason(
    evaluated_at_utc: datetime,
    evaluated_at_monotonic_ns: int,
    reason: TrustedTimeReason,
) -> None:
    prior = _evaluate(None, _sample(second=1, sequence=1), second=1)

    state = evaluate_trusted_time(
        prior,
        None,
        evaluated_at_utc=evaluated_at_utc,
        evaluated_at_monotonic_ns=evaluated_at_monotonic_ns,
    ).state

    assert state.health is TrustedTimeHealth.BLOCKED
    assert state.reason is reason


def test_sample_and_evaluation_identity_are_deterministic_and_tamper_sensitive() -> None:
    sample = _sample(second=0)
    same = _sample(second=0)
    changed = replace(sample, source_evidence_sha256="c" * 64)
    changed_uncertainty = replace(
        sample,
        source_uncertainty_milliseconds=Decimal("0.0000000001"),
    )
    first = evaluate_trusted_time(
        None,
        sample,
        evaluated_at_utc=BASE,
        evaluated_at_monotonic_ns=0,
    )
    repeated = evaluate_trusted_time(
        None,
        same,
        evaluated_at_utc=BASE,
        evaluated_at_monotonic_ns=0,
    )

    assert sample.semantic_sha256 == same.semantic_sha256
    assert sample.canonical_json == same.canonical_json
    assert changed.semantic_sha256 != sample.semantic_sha256
    assert changed_uncertainty.semantic_sha256 != sample.semantic_sha256
    assert first.semantic_sha256 == repeated.semantic_sha256

    with pytest.raises(TrustedTimeError, match="seal"):
        replace(first.state, previous_state_sha256="d" * 64)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("clock_recovery_qualified", True),
        ("hard_failure_latched", True),
        ("health", TrustedTimeHealth.WARNING),
        ("reason", TrustedTimeReason.WITHIN_LIMIT),
        ("healthy_since_monotonic_ns", None),
    ],
)
def test_reducer_state_rejects_derived_field_forgery(
    field_name: str,
    value: object,
) -> None:
    state = _evaluate(None, _sample(second=0), second=0)

    with pytest.raises(TrustedTimeError, match="seal"):
        replace(state, **{field_name: value})  # type: ignore[arg-type]


def test_evaluation_recomputes_reducer_semantics() -> None:
    sample = _sample(second=0)
    evaluation = evaluate_trusted_time(
        None,
        sample,
        evaluated_at_utc=BASE,
        evaluated_at_monotonic_ns=0,
    )
    unavailable = evaluate_trusted_time(
        evaluation.state,
        None,
        evaluated_at_utc=BASE + timedelta(seconds=1),
        evaluated_at_monotonic_ns=SECOND_NS,
    )

    with pytest.raises(TrustedTimeError, match="predecessor"):
        TrustedTimeEvaluation(
            prior=None,
            sample=None,
            state=unavailable.state,
        )


def test_sample_rejects_non_utc_and_regressing_probe_intervals() -> None:
    with pytest.raises(TrustedTimeError, match="UTC"):
        replace(_sample(second=0), trusted_at_utc=BASE.astimezone(timezone(timedelta(hours=-4))))
    with pytest.raises(TrustedTimeError, match="interval regressed"):
        replace(
            _sample(second=0),
            probe_started_at_utc=BASE + timedelta(seconds=1),
        )
    with pytest.raises(TrustedTimeError, match="monotonic interval regressed"):
        replace(
            _sample(second=0),
            probe_started_monotonic_ns=1,
            probe_completed_monotonic_ns=0,
        )


@pytest.mark.parametrize(
    "uncertainty",
    [Decimal("-0.0000000001"), Decimal("100.0000000001"), Decimal("NaN"), 0],
)
def test_sample_rejects_uncertainty_outside_exact_approved_decimal_contract(
    uncertainty: object,
) -> None:
    with pytest.raises(TrustedTimeError, match=r"uncertainty|Decimal"):
        replace(
            _sample(second=0),
            source_uncertainty_milliseconds=uncertainty,  # type: ignore[arg-type]
        )


def test_probe_duration_and_cross_clock_elapsed_limits_are_exact() -> None:
    exact_duration = _sample(
        second=1,
        sequence=1,
        started_second=0,
    )
    exact_elapsed_delta = replace(
        _sample(second=0),
        probe_completed_monotonic_ns=250_000_000,
    )

    assert exact_duration.probe_completed_monotonic_ns == SECOND_NS
    assert exact_elapsed_delta.probe_completed_monotonic_ns == 250_000_000
    with pytest.raises(TrustedTimeError, match="duration exceeded"):
        replace(
            exact_duration,
            probe_completed_monotonic_ns=SECOND_NS + 1,
        )
    with pytest.raises(TrustedTimeError, match="intervals diverged"):
        replace(
            _sample(second=0),
            probe_completed_monotonic_ns=250_000_001,
        )


def test_policy_digest_pins_the_exact_budget_comparators() -> None:
    assert TRUSTED_TIME_POLICY.warning_offset_milliseconds == Decimal("250")
    assert TRUSTED_TIME_POLICY.hard_offset_milliseconds == Decimal("1000")
    assert TRUSTED_TIME_POLICY.maximum_source_uncertainty_milliseconds == Decimal("100")
    assert TRUSTED_TIME_POLICY.maximum_probe_duration_ns == SECOND_NS
    assert TRUSTED_TIME_POLICY.maximum_sample_age_ns == 30 * SECOND_NS
    assert TRUSTED_TIME_POLICY.maximum_cadence_gap_ns == 30 * SECOND_NS
    assert TRUSTED_TIME_POLICY.healthy_recovery_window_ns == 60 * SECOND_NS
    assert len(TRUSTED_TIME_POLICY.semantic_sha256) == 64
    assert "policy" not in signature(evaluate_trusted_time).parameters
