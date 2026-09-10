"""Pure daily reference targets from an explicitly bounded, causal input view."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import (
    ROUND_FLOOR,
    Clamped,
    Context,
    Decimal,
    DecimalException,
    DivisionByZero,
    FloatOperation,
    InvalidOperation,
    Overflow,
    Subnormal,
    Underflow,
    localcontext,
)

from packages.domain.canonical import canonical_persisted_decimal
from packages.domain.decimal_math import (
    DECIMAL_ARITHMETIC_EMAX,
    DECIMAL_ARITHMETIC_EMIN,
    DECIMAL_ARITHMETIC_PRECISION,
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_sum,
)
from packages.domain.models import PositionTarget
from packages.domain.research_dataset import PERSONAL_SYMBOLS

REFERENCE_ARITHMETIC_VERSION = "personal-daily-reference/1"

# Downward division prevents rounding a quotient just below an integer upward
# before the whole-share floor. Neither precision nor traps come from the caller.
_SIZING_CONTEXT = Context(
    prec=DECIMAL_ARITHMETIC_PRECISION,
    rounding=ROUND_FLOOR,
    Emin=DECIMAL_ARITHMETIC_EMIN,
    Emax=DECIMAL_ARITHMETIC_EMAX,
    capitals=1,
    clamp=0,
    flags=[],
    traps=[
        Clamped,
        DivisionByZero,
        FloatOperation,
        InvalidOperation,
        Overflow,
        Subnormal,
        Underflow,
    ],
)


def _nonnegative_decimal(value: Decimal, name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite() or value < 0:
        raise ValueError(f"{name} must be a finite, non-negative exact Decimal")
    return canonical_persisted_decimal(value, name)


def _positive_decimal(value: Decimal, name: str) -> Decimal:
    result = _nonnegative_decimal(value, name)
    if result == 0:
        raise ValueError(f"{name} must be positive")
    return result


@dataclass(frozen=True, slots=True)
class ReferenceConfiguration:
    kind: str = "buy_hold"
    lookback: int = 200
    allocation: Decimal = Decimal("0.25")
    rebalance_sessions: int | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in ("buy_hold", "trend_sma"):
            raise ValueError("reference kind must be buy_hold or trend_sma")
        if type(self.lookback) is not int or self.lookback <= 0:
            raise ValueError("reference lookback must be a positive integer")
        allocation = _nonnegative_decimal(self.allocation, "reference allocation")
        if allocation > Decimal("0.25"):
            raise ValueError("reference allocation cannot exceed 0.25 per instrument")
        object.__setattr__(self, "allocation", allocation)
        if self.rebalance_sessions is not None and (
            type(self.rebalance_sessions) is not int or self.rebalance_sessions <= 0
        ):
            raise ValueError("reference rebalance interval must be a positive integer")


@dataclass(frozen=True, slots=True)
class ReferenceDecision:
    targets: tuple[PositionTarget, ...]
    should_emit: bool
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.should_emit) is not bool:
            raise ValueError("reference emission flag must be boolean")
        if type(self.targets) is not tuple or any(
            type(target) is not PositionTarget for target in self.targets
        ):
            raise ValueError("reference targets must be an immutable tuple of PositionTarget")
        identifiers = tuple(target.instrument_id for target in self.targets)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("reference targets must have sorted unique instrument IDs")
        if type(self.reasons) is not tuple or any(
            type(reason) is not str or not reason or reason != reason.strip()
            for reason in self.reasons
        ):
            raise ValueError("reference reasons must be immutable nonempty strings")
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise ValueError("reference reasons must be sorted and unique")
        if self.should_emit:
            if not self.targets or self.reasons:
                raise ValueError("an emitted reference decision requires targets and no reasons")
        elif self.targets or not self.reasons:
            raise ValueError("a no-target reference decision requires reasons and no targets")


def _instruments(instrument_symbols: tuple[tuple[str, str], ...]) -> dict[str, str]:
    if type(instrument_symbols) is not tuple or not instrument_symbols:
        raise ValueError("reference universe must be a nonempty immutable tuple")
    instruments: dict[str, str] = {}
    symbols: set[str] = set()
    for entry in instrument_symbols:
        if type(entry) is not tuple or len(entry) != 2:
            raise ValueError("reference instrument bindings must be pairs")
        instrument_id, symbol = entry
        if (
            type(instrument_id) is not str
            or not instrument_id
            or instrument_id != instrument_id.strip()
            or instrument_id in instruments
        ):
            raise ValueError("reference instrument IDs must be distinct nonempty trimmed strings")
        if type(symbol) is not str or symbol not in PERSONAL_SYMBOLS or symbol in symbols:
            raise ValueError("reference symbols must be distinct allowed uppercase ETF symbols")
        instruments[instrument_id] = symbol
        symbols.add(symbol)
    return instruments


def _bindings(
    values: tuple[tuple[str, Decimal | None], ...],
    instruments: dict[str, str],
    *,
    name: str,
    allow_missing: bool = False,
    quantities: bool = False,
) -> dict[str, Decimal | None]:
    if type(values) is not tuple:
        raise ValueError(f"{name} must be an immutable tuple")
    result: dict[str, Decimal | None] = {}
    for entry in values:
        if type(entry) is not tuple or len(entry) != 2:
            raise ValueError(f"{name} entries must be pairs")
        instrument_id, value = entry
        if type(instrument_id) is not str or instrument_id not in instruments:
            raise ValueError(f"{name} includes an instrument outside the configured universe")
        if instrument_id in result:
            raise ValueError(f"{name} repeats an instrument")
        if value is None and allow_missing:
            result[instrument_id] = None
        elif quantities:
            if type(value) is not Decimal:
                raise ValueError(f"{name} quantities require exact Decimal values")
            result[instrument_id] = PositionTarget(
                instrument_id, instruments[instrument_id], value
            ).quantity
        else:
            if type(value) is not Decimal:
                raise ValueError(f"{name} prices require exact Decimal values")
            result[instrument_id] = _positive_decimal(value, name)
    return result


def _history(
    history: tuple[tuple[date, tuple[tuple[str, Decimal | None], ...]], ...],
    expected_sessions: tuple[date, ...],
    instruments: dict[str, str],
) -> dict[date, dict[str, Decimal | None]]:
    if type(expected_sessions) is not tuple or any(
        type(session) is not date for session in expected_sessions
    ):
        raise ValueError("expected sessions must be an immutable tuple of exact dates")
    if expected_sessions != tuple(sorted(set(expected_sessions))):
        raise ValueError("expected sessions must be strictly increasing and unique")
    if type(history) is not tuple:
        raise ValueError("reference history must be an immutable tuple")
    expected = set(expected_sessions)
    result: dict[date, dict[str, Decimal | None]] = {}
    previous: date | None = None
    for entry in history:
        if type(entry) is not tuple or len(entry) != 2:
            raise ValueError("reference history entries must be session/value pairs")
        session, values = entry
        if type(session) is not date or session not in expected:
            raise ValueError(
                "reference history contains a session outside the causal calendar view"
            )
        if previous is not None and session <= previous:
            raise ValueError("reference history sessions must be strictly increasing and unique")
        result[session] = _bindings(
            values, instruments, name="reference history", allow_missing=True
        )
        previous = session
    return result


def _floor_quantity(
    *,
    nav: Decimal,
    allocation: Decimal,
    price: Decimal,
    reserve_fraction: Decimal,
    fee_per_share: Decimal,
) -> Decimal:
    budget = exact_decimal_multiply(nav, allocation)
    per_share = exact_decimal_add(
        exact_decimal_multiply(price, exact_decimal_add(Decimal(1), reserve_fraction)),
        fee_per_share,
    )
    try:
        with localcontext(_SIZING_CONTEXT):
            return (budget / per_share).to_integral_value(rounding=ROUND_FLOOR)
    except DecimalException as error:
        raise ValueError("reference sizing exceeds the exact decimal arithmetic policy") from error


def reference_targets(
    configuration: ReferenceConfiguration,
    *,
    instrument_symbols: tuple[tuple[str, str], ...],
    history: tuple[tuple[date, tuple[tuple[str, Decimal | None], ...]], ...],
    expected_sessions: tuple[date, ...],
    current_quantities: tuple[tuple[str, Decimal], ...],
    nav: Decimal | None,
    reference_prices: tuple[tuple[str, Decimal], ...],
    scored_session_index: int,
    previously_allocated: bool,
    reserve_fraction: Decimal = Decimal("0.01"),
    fee_per_share: Decimal = Decimal("0.01"),
) -> ReferenceDecision:
    """Return desired whole-share holdings, never orders or risk authority.

    ``expected_sessions`` is the caller's calendar prefix through the current
    causal session. History outside that prefix rejects. Its prices are the
    caller's pinned adjusted-close feature series; sizing uses separate raw
    reference prices. Missing expected history breaks the contiguous window.

    Buy/hold allocates once, then at positive scored indices divisible by its
    configured interval. Trend evaluates daily regardless of that interval.
    ``previously_allocated`` is acknowledged allocation state supplied by the
    engine. Missing current quantities denote zero. Full desired targets are
    returned even when equal to filled holdings: only the commitment-aware
    converter can decide whether an intent is needed.
    """
    if type(configuration) is not ReferenceConfiguration:
        raise ValueError("reference configuration requires the exact versioned type")
    if type(scored_session_index) is not int or scored_session_index < 0:
        raise ValueError("scored session index must be a non-negative integer")
    if type(previously_allocated) is not bool:
        raise ValueError("previously allocated must be boolean")
    instruments = _instruments(instrument_symbols)
    _bindings(current_quantities, instruments, name="current quantities", quantities=True)
    prices = _bindings(reference_prices, instruments, name="raw reference prices")
    rows = _history(history, expected_sessions, instruments)
    current_nav = None if nav is None else _nonnegative_decimal(nav, "reference NAV")
    reserve = _nonnegative_decimal(reserve_fraction, "reference reserve fraction")
    fee = _nonnegative_decimal(fee_per_share, "reference per-share fee")

    reasons: list[str] = []
    if current_nav is None:
        reasons.append("NAV_UNAVAILABLE")
    elif current_nav == 0:
        reasons.append("NAV_NOT_POSITIVE")
    latest = rows.get(expected_sessions[-1], {}) if expected_sessions else {}
    above_mean: dict[str, bool] = {}
    for instrument_id in sorted(instruments):
        if instrument_id not in prices:
            reasons.append(f"REFERENCE_PRICE_UNAVAILABLE:{instrument_id}")
        if latest.get(instrument_id) is None:
            reasons.append(f"CURRENT_CLOSE_UNAVAILABLE:{instrument_id}")
        if configuration.kind == "trend_sma":
            window: list[Decimal] = []
            for session in reversed(expected_sessions):
                close = rows.get(session, {}).get(instrument_id)
                if close is None:
                    break
                window.append(close)
                if len(window) == configuration.lookback:
                    break
            if len(window) != configuration.lookback:
                reasons.append(f"INSUFFICIENT_CONTIGUOUS_HISTORY:{instrument_id}")
            else:
                # Compare to the exact mean by cross-multiplication; no rounded
                # division can change strict-above/equality behavior.
                above_mean[instrument_id] = exact_decimal_multiply(
                    window[0], Decimal(configuration.lookback)
                ) > exact_decimal_sum(window)
    if reasons:
        return ReferenceDecision((), False, tuple(sorted(set(reasons))))

    if configuration.kind == "buy_hold" and previously_allocated:
        interval = configuration.rebalance_sessions
        if interval is None or scored_session_index == 0 or scored_session_index % interval:
            return ReferenceDecision((), False, ("REBALANCE_NOT_DUE",))

    if current_nav is None:
        raise RuntimeError("validated reference NAV was unavailable")
    targets: list[PositionTarget] = []
    for instrument_id, symbol in sorted(instruments.items()):
        price = prices[instrument_id]
        if price is None:
            raise RuntimeError("validated raw reference price was unavailable")
        invested = configuration.kind == "buy_hold" or above_mean[instrument_id]
        quantity = (
            _floor_quantity(
                nav=current_nav,
                allocation=configuration.allocation,
                price=price,
                reserve_fraction=reserve,
                fee_per_share=fee,
            )
            if invested
            else Decimal(0)
        )
        targets.append(PositionTarget(instrument_id, symbol, quantity))
    return ReferenceDecision(tuple(targets), True, ())
