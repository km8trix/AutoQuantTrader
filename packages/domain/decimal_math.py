"""Versioned, ambient-context-independent Decimal arithmetic."""

from __future__ import annotations

from collections.abc import Iterable
from decimal import (
    ROUND_HALF_EVEN,
    Clamped,
    Context,
    Decimal,
    DecimalException,
    DivisionByZero,
    FloatOperation,
    Inexact,
    InvalidOperation,
    Overflow,
    Rounded,
    Subnormal,
    Underflow,
    localcontext,
)

from packages.domain.canonical import canonical_decimal

DECIMAL_ARITHMETIC_VERSION = "decimal64-e63-exact-v1"
DECIMAL_ARITHMETIC_PRECISION = 64
DECIMAL_ARITHMETIC_EMIN = -63
DECIMAL_ARITHMETIC_EMAX = 63

_BASE_TRAPS = [
    Clamped,
    DivisionByZero,
    FloatOperation,
    InvalidOperation,
    Overflow,
    Subnormal,
    Underflow,
]

_EXACT_CONTEXT = Context(
    prec=DECIMAL_ARITHMETIC_PRECISION,
    rounding=ROUND_HALF_EVEN,
    Emin=DECIMAL_ARITHMETIC_EMIN,
    Emax=DECIMAL_ARITHMETIC_EMAX,
    capitals=1,
    clamp=0,
    flags=[],
    traps=[*_BASE_TRAPS, Inexact, Rounded],
)
_DIVISION_CONTEXT = Context(
    prec=DECIMAL_ARITHMETIC_PRECISION,
    rounding=ROUND_HALF_EVEN,
    Emin=DECIMAL_ARITHMETIC_EMIN,
    Emax=DECIMAL_ARITHMETIC_EMAX,
    capitals=1,
    clamp=0,
    flags=[],
    traps=_BASE_TRAPS,
)


def _operands(left: Decimal, right: Decimal) -> tuple[Decimal, Decimal]:
    return canonical_decimal(left), canonical_decimal(right)


def _arithmetic_error(operation: str) -> ValueError:
    return ValueError(
        f"{operation} exceeds the {DECIMAL_ARITHMETIC_VERSION} exact arithmetic policy"
    )


def exact_decimal_add(left: Decimal, right: Decimal) -> Decimal:
    """Add exactly under the versioned policy or fail closed."""

    left, right = _operands(left, right)
    try:
        with localcontext(_EXACT_CONTEXT):
            result = left + right
    except DecimalException as error:
        raise _arithmetic_error("decimal addition") from error
    return canonical_decimal(result)


def exact_decimal_subtract(left: Decimal, right: Decimal) -> Decimal:
    """Subtract exactly under the versioned policy or fail closed."""

    left, right = _operands(left, right)
    try:
        with localcontext(_EXACT_CONTEXT):
            result = left - right
    except DecimalException as error:
        raise _arithmetic_error("decimal subtraction") from error
    return canonical_decimal(result)


def exact_decimal_multiply(left: Decimal, right: Decimal) -> Decimal:
    """Multiply exactly under the versioned policy or fail closed."""

    left, right = _operands(left, right)
    try:
        with localcontext(_EXACT_CONTEXT):
            result = left * right
    except DecimalException as error:
        raise _arithmetic_error("decimal multiplication") from error
    return canonical_decimal(result)


def exact_decimal_sum(values: Iterable[Decimal]) -> Decimal:
    """Sum exactly under the versioned policy or fail closed."""

    total = Decimal(0)
    for value in values:
        total = exact_decimal_add(total, value)
    return total


def deterministic_decimal_divide(left: Decimal, right: Decimal) -> Decimal:
    """Divide under the versioned 64-digit half-even projection policy."""

    left, right = _operands(left, right)
    try:
        with localcontext(_DIVISION_CONTEXT):
            result = left / right
    except DecimalException as error:
        raise ValueError(
            f"decimal division violates the {DECIMAL_ARITHMETIC_VERSION} policy"
        ) from error
    return canonical_decimal(result)
