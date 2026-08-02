from __future__ import annotations

import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal, localcontext

import pytest

from packages.domain.canonical import (
    canonical_decimal,
    canonical_decimal_text,
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
    canonical_persisted_decimal_from_scaled_integer,
)
from packages.domain.decimal_math import (
    DECIMAL_ARITHMETIC_EMAX,
    DECIMAL_ARITHMETIC_EMIN,
    DECIMAL_ARITHMETIC_VERSION,
    exact_decimal_add,
    exact_decimal_multiply,
)
from packages.domain.models import DecisionStatus, RiskDecision
from packages.domain.risk import RiskLimits, evaluate_risk_decision, intent_payload_hash
from packages.domain.walking_thread import WalkingThread


def test_canonical_decimal_is_exact_scale_independent_and_context_free() -> None:
    value = Decimal("12345678901234567890123456789.1000")

    with localcontext() as context:
        context.prec = 3
        canonical = canonical_decimal(value)

    assert canonical == value
    assert canonical.as_tuple() == Decimal("12345678901234567890123456789.1").as_tuple()
    assert canonical_decimal(Decimal("100.00")).as_tuple() == Decimal("1E+2").as_tuple()
    assert canonical_decimal(Decimal("-0.000")).as_tuple() == Decimal("0").as_tuple()


def test_canonical_decimal_text_is_compact_and_collision_resistant() -> None:
    assert canonical_decimal_text(Decimal("100.00")) == "1e2"
    assert canonical_decimal_text(Decimal("1.00e2")) == "1e2"
    assert canonical_decimal_text(Decimal("-0.0012300")) == "-123e-5"
    assert canonical_decimal_text(Decimal("-0")) == "0"
    assert len(canonical_decimal_text(Decimal("1e100000"))) < 32
    assert canonical_decimal_text(
        Decimal("12345678901234567890123456789.1")
    ) != canonical_decimal_text(Decimal("12345678901234567890123456789.2"))


@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")])
def test_canonical_decimal_rejects_nonfinite_values(value: Decimal) -> None:
    with pytest.raises(ValueError, match="finite"):
        canonical_decimal(value)


def test_persisted_decimal_requires_exact_numeric_28_10_representation() -> None:
    accepted = Decimal("999999999999999999.1234567890")

    assert canonical_persisted_decimal(accepted, "amount") == accepted
    with pytest.raises(ValueError, match=r"NUMERIC\(28, 10\)"):
        canonical_persisted_decimal(Decimal("1e18"), "amount")
    with pytest.raises(ValueError, match=r"NUMERIC\(28, 10\)"):
        canonical_persisted_decimal(Decimal("1e-11"), "amount")


def test_scaled_persisted_decimal_construction_is_exact_and_context_free() -> None:
    with localcontext() as context:
        context.prec = 2
        value = canonical_persisted_decimal_from_scaled_integer(
            1_234_567,
            scale=3,
            field_name="amount",
        )

    assert value == Decimal("1234.567")
    with pytest.raises(ValueError, match=r"NUMERIC\(28, 10\)"):
        canonical_persisted_decimal_from_scaled_integer(
            1,
            scale=11,
            field_name="amount",
        )


def test_decimal_arithmetic_has_literal_bounds_and_fails_closed() -> None:
    assert DECIMAL_ARITHMETIC_EMIN == -63
    assert DECIMAL_ARITHMETIC_EMAX == 63
    assert exact_decimal_multiply(Decimal("3"), Decimal("1.23456789")) == Decimal("3.70370367")
    with pytest.raises(ValueError, match=DECIMAL_ARITHMETIC_VERSION):
        exact_decimal_add(Decimal("9e63"), Decimal("9e63"))


def test_decimal_arithmetic_context_does_not_inherit_mutated_default_context() -> None:
    script = """
from decimal import Clamped, Decimal, DefaultContext, ROUND_DOWN
DefaultContext.prec = 2
DefaultContext.rounding = ROUND_DOWN
DefaultContext.capitals = 0
DefaultContext.clamp = 1
DefaultContext.traps[Clamped] = True
from packages.domain.decimal_math import exact_decimal_multiply
assert exact_decimal_multiply(Decimal('3'), Decimal('1.23456789')) == Decimal('3.70370367')
"""

    subprocess.run([sys.executable, "-c", script], check=True)


def test_typed_canonical_json_is_order_independent_and_explicit() -> None:
    first = {
        "z": (Decimal("100.00"), True),
        "a": frozenset({"SPY", "QQQ"}),
    }
    second = {
        "a": frozenset({"QQQ", "SPY"}),
        "z": (Decimal("1e2"), True),
    }

    assert canonical_json_text(first) == canonical_json_text(second)
    assert canonical_json_bytes(first) == canonical_json_text(first).encode("utf-8")
    assert canonical_json_text(1) != canonical_json_text("1")
    assert canonical_json_text(1) != canonical_json_text(True)
    assert canonical_json_text(("a", "b")) != canonical_json_text(["a", "b"])


def test_typed_canonical_json_normalizes_aware_datetimes_to_utc() -> None:
    utc_value = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
    offset_value = datetime(
        2026,
        7,
        18,
        8,
        0,
        tzinfo=timezone(-timedelta(hours=4)),
    )

    assert canonical_json_text(utc_value) == canonical_json_text(offset_value)
    with pytest.raises(ValueError, match="timezone-aware"):
        canonical_json_text(utc_value.replace(tzinfo=None))
    with pytest.raises(TypeError, match="unsupported"):
        canonical_json_text(1.0)


def test_risk_payload_hash_uses_scale_independent_compact_decimals() -> None:
    intent = WalkingThread.run().intent
    rescaled = replace(
        intent,
        quantity=Decimal("10.000"),
        reference_price=Decimal("100.0"),
    )

    assert intent_payload_hash(intent) == intent_payload_hash(rescaled)
    with pytest.raises(ValueError, match=r"NUMERIC\(28, 10\)"):
        replace(intent, reference_price=Decimal("1e100000"))
    assert intent_payload_hash(
        replace(intent, reference_price=Decimal("123456789012345678.1234567891"))
    ) != intent_payload_hash(
        replace(intent, reference_price=Decimal("123456789012345678.1234567892"))
    )


def test_risk_decision_is_independent_of_ambient_decimal_context() -> None:
    intent = replace(
        WalkingThread.run().intent,
        quantity=Decimal("3"),
        reference_price=Decimal("1.23456789"),
    )
    limits = RiskLimits(
        allowed_instruments=frozenset({intent.instrument_id}),
        max_order_quantity=Decimal("100"),
        max_order_notional=Decimal("3.7038"),
        minimum_cash_buffer=Decimal("0"),
        estimated_fee=Decimal("0"),
    )

    def evaluate(precision: int, capitals: int) -> RiskDecision:
        with localcontext() as context:
            context.prec = precision
            context.capitals = capitals
            return evaluate_risk_decision(
                intent,
                limits,
                Decimal("100"),
                intent.created_at,
            )

    low_precision = evaluate(4, 0)
    high_precision = evaluate(40, 1)

    assert low_precision == high_precision
    assert low_precision.status is DecisionStatus.APPROVED
