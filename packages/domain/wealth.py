"""Pure flow-neutral wealth arithmetic over accepted causal valuation rows."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import (
    ROUND_HALF_EVEN,
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
from itertools import pairwise

from packages.domain.canonical import canonical_decimal, canonical_persisted_decimal

DERIVED_ARITHMETIC_VERSION = "personal-derived-decimal64-half-even-v1"
_ROLES = frozenset({"baseline", "valuation", "pre_flow", "post_flow"})


def derived_context() -> Context:
    """Return a fresh context for ``with localcontext(derived_context())``.

    Derived ratios may round to 64 significant digits; they are never quantized
    to persisted monetary scale. Explicit parameters avoid ambient/default
    precision, rounding, flags and trap settings, including at import time.
    """

    return Context(
        prec=64,
        rounding=ROUND_HALF_EVEN,
        Emin=-999999,
        Emax=999999,
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


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be nonempty trimmed text")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{field_name} cannot contain control characters")


def _require_identity(point_id: str, sequence: int) -> None:
    _require_text(point_id, "point_id")
    if type(sequence) is not int or sequence < 0:
        raise ValueError("sequence must be a nonnegative integer")


def _reasons(values: tuple[str, ...]) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise ValueError("reasons must be an immutable tuple")
    for value in values:
        _require_text(value, "reason")
    return tuple(sorted(set(values)))


def _derived_nav(value: Decimal) -> Decimal:
    nav = canonical_decimal(value)
    context = derived_context()
    if nav and (
        len(nav.as_tuple().digits) > context.prec
        or not context.Emin <= nav.adjusted() <= context.Emax
    ):
        raise ValueError(f"wealth NAV exceeds {DERIVED_ARITHMETIC_VERSION} precision/range")
    return nav


@dataclass(frozen=True, slots=True)
class WealthPoint:
    """A source NAV, with explicit unusable-valuation reasons when necessary.

    NAV accepts exact canonical values with up to 64 significant digits and
    adjusted exponents inside the derived context's normal range. This permits
    analytical benchmark NAV without monetary quantization; ledger producers
    retain their own persisted-money validation. Signed flows remain exact
    NUMERIC(28, 10) money. Any nonempty ``reasons`` makes a point unusable for
    authoritative wealth arithmetic, including a retained stale estimate.
    """

    point_id: str
    sequence: int
    nav: Decimal | None
    signed_flow: Decimal = Decimal(0)
    flow_pair_id: str | None = None
    role: str = "valuation"
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_identity(self.point_id, self.sequence)
        if type(self.role) is not str or self.role not in _ROLES:
            raise ValueError("unsupported wealth point role")
        if self.nav is not None:
            object.__setattr__(self, "nav", _derived_nav(self.nav))
        object.__setattr__(
            self,
            "signed_flow",
            canonical_persisted_decimal(self.signed_flow, "wealth signed flow"),
        )
        object.__setattr__(self, "reasons", _reasons(self.reasons))
        if self.role in {"pre_flow", "post_flow"}:
            if self.flow_pair_id is None:
                raise ValueError("flow boundary requires a flow_pair_id")
            _require_text(self.flow_pair_id, "flow_pair_id")
        elif self.flow_pair_id is not None:
            raise ValueError("only flow boundaries can carry a flow_pair_id")
        if self.role != "post_flow" and self.signed_flow != 0:
            raise ValueError("only post_flow can carry a signed flow")


@dataclass(frozen=True, slots=True)
class WealthValue:
    """Derived growth, linked wealth and drawdown, or a reasoned null path."""

    point_id: str
    sequence: int
    growth: Decimal | None
    wealth: Decimal | None
    drawdown: Decimal | None
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_identity(self.point_id, self.sequence)
        object.__setattr__(self, "reasons", _reasons(self.reasons))
        values = (self.growth, self.wealth, self.drawdown)
        if any(value is None for value in values):
            if not all(value is None for value in values) or not self.reasons:
                raise ValueError("undefined wealth must have all null values and reasons")
            return
        if self.reasons:
            raise ValueError("defined wealth cannot carry unusable-valuation reasons")
        for field_name in ("growth", "wealth", "drawdown"):
            object.__setattr__(self, field_name, canonical_decimal(getattr(self, field_name)))
        assert self.growth is not None and self.wealth is not None and self.drawdown is not None
        if self.growth <= 0 or self.wealth <= 0 or not 0 <= self.drawdown <= 1:
            raise ValueError("defined wealth requires positive growth/wealth and bounded drawdown")


def _validate_path(points: tuple[WealthPoint, ...]) -> None:
    if type(points) is not tuple or not points:
        raise ValueError("wealth path requires a nonempty immutable tuple")
    if any(type(point) is not WealthPoint for point in points):
        raise ValueError("wealth path requires exact WealthPoint rows")
    if points[0].role != "baseline" or any(point.role == "baseline" for point in points[1:]):
        raise ValueError("wealth path requires exactly one baseline as its first point")
    if any(current.sequence <= previous.sequence for previous, current in pairwise(points)):
        raise ValueError("wealth point sequences must be strictly increasing")
    if len({point.point_id for point in points}) != len(points):
        raise ValueError("wealth point IDs must be unique")
    pair_ids: set[str] = set()
    for index, point in enumerate(points):
        if point.role == "pre_flow":
            if index + 1 == len(points) or points[index + 1].role != "post_flow":
                raise ValueError("pre_flow must be immediately followed by post_flow")
            following = points[index + 1]
            if point.flow_pair_id != following.flow_pair_id:
                raise ValueError("adjacent flow boundaries must have matching pair IDs")
            assert point.flow_pair_id is not None
            if point.flow_pair_id in pair_ids:
                raise ValueError("flow pair IDs cannot be reused")
            pair_ids.add(point.flow_pair_id)
            if point.nav is not None and following.nav is not None:
                # Analytical NAV uses this pinned derived precision. Persisted
                # monetary NAV plus persisted flows remains exact here.
                with localcontext(derived_context()):
                    expected = point.nav + following.signed_flow
                if following.nav != expected:
                    raise ValueError("post-flow NAV must equal pre-flow NAV plus signed flow")
        elif point.role == "post_flow" and points[index - 1].role != "pre_flow":
            raise ValueError("post_flow must immediately follow pre_flow")


def _valuation_reasons(point: WealthPoint) -> tuple[str, ...]:
    reasons = set(point.reasons)
    if point.nav is None:
        reasons.add(
            f"missing_{point.role}_valuation"
            if point.role in {"pre_flow", "post_flow"}
            else "missing_valuation"
        )
    elif point.nav <= 0:
        reasons.add("nonpositive_nav")
    return tuple(sorted(reasons))


def derive_wealth_path(points: tuple[WealthPoint, ...]) -> tuple[WealthValue, ...]:
    """Link causal NAV changes, skipping paired capital transfers as returns.

    A valid baseline has growth/wealth 1 and drawdown 0; it is not a scored return.
    Any unusable valuation latches all subsequent outputs null. A new independent
    interval needs a separate call with its own baseline; gaps are never bridged.
    """

    _validate_path(points)
    result: list[WealthValue] = []
    blocked: set[str] = set()
    wealth = peak = Decimal(1)
    with localcontext(derived_context()):
        for index, point in enumerate(points):
            previously_blocked = bool(blocked)
            blocked.update(_valuation_reasons(point))
            if blocked:
                if previously_blocked:
                    blocked.add("incomplete_return_path")
                result.append(
                    WealthValue(
                        point.point_id, point.sequence, None, None, None, tuple(sorted(blocked))
                    )
                )
                continue
            assert point.nav is not None
            try:
                if index == 0 or point.role == "post_flow":
                    growth = Decimal(1)
                else:
                    prior_nav = points[index - 1].nav
                    assert prior_nav is not None
                    growth = point.nav / prior_nav
                wealth = wealth * growth
                peak = max(peak, wealth)
                drawdown = Decimal(1) - wealth / peak
            except DecimalException as error:
                raise ValueError(
                    f"wealth arithmetic violates {DERIVED_ARITHMETIC_VERSION}"
                ) from error
            result.append(WealthValue(point.point_id, point.sequence, growth, wealth, drawdown, ()))
    return tuple(result)
