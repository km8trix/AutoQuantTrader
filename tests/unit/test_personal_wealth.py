"""Independent cash-flow arithmetic and fail-closed wealth-path cases."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from decimal import (
    ROUND_DOWN,
    ROUND_HALF_EVEN,
    Decimal,
    Inexact,
    Rounded,
    localcontext,
)

import pytest

from packages.domain.wealth import WealthPoint, WealthValue, derive_wealth_path, derived_context


def point(
    sequence: int,
    nav: str | None,
    *,
    role: str = "valuation",
    pair: str | None = None,
    flow: str = "0",
    reasons: tuple[str, ...] = (),
) -> WealthPoint:
    return WealthPoint(
        point_id=f"point-{sequence}",
        sequence=sequence,
        nav=None if nav is None else Decimal(nav),
        signed_flow=Decimal(flow),
        flow_pair_id=pair,
        role=role,
        reasons=reasons,
    )


@pytest.mark.parametrize(
    ("flow", "post_nav", "terminal_nav", "naive_return"),
    [("500", "1600", "1760", "0.26"), ("-200", "900", "990", "0.19")],
)
def test_e4_e5_link_to_twenty_one_percent(
    flow: str, post_nav: str, terminal_nav: str, naive_return: str
) -> None:
    rows = (
        point(0, "1000", role="baseline"),
        point(1, "1100", role="pre_flow", pair="external-flow"),
        point(2, post_nav, role="post_flow", pair="external-flow", flow=flow),
        point(3, terminal_nav),
    )
    values = derive_wealth_path(rows)
    assert tuple(value.growth for value in values) == tuple(
        Decimal(value) for value in ("1", "1.1", "1", "1.1")
    )
    assert tuple(value.wealth for value in values) == tuple(
        Decimal(value) for value in ("1", "1.1", "1.1", "1.21")
    )
    assert values[-1].wealth == Decimal("1.21")
    assert values[-1].wealth - 1 != Decimal(naive_return)
    assert all(value.drawdown == 0 and value.reasons == () for value in values)


def test_multiple_flow_pairs_use_sequences_and_preserve_flow_neutral_drawdown() -> None:
    values = derive_wealth_path(
        (
            point(10, "1000", role="baseline"),
            point(15, "1100", role="pre_flow", pair="contribution"),
            point(16, "1600", role="post_flow", pair="contribution", flow="500"),
            point(20, "1760", role="pre_flow", pair="withdrawal"),
            point(21, "1560", role="post_flow", pair="withdrawal", flow="-200"),
            point(30, "1716"),
            point(40, "1544.4"),
        )
    )
    assert values[4].growth == 1
    assert values[4].wealth == Decimal("1.21")
    assert values[4].drawdown == 0
    assert values[5].wealth == Decimal("1.331")
    assert values[6].wealth == Decimal("1.1979")
    assert values[6].drawdown == Decimal("0.1")
    assert tuple(value.sequence for value in values) == (10, 15, 16, 20, 21, 30, 40)


def test_flow_only_account_remains_flat() -> None:
    values = derive_wealth_path(
        (
            point(0, "1000", role="baseline"),
            point(1, "1000", role="pre_flow", pair="in"),
            point(2, "1500", role="post_flow", pair="in", flow="500"),
            point(3, "1500", role="pre_flow", pair="out"),
            point(4, "1300", role="post_flow", pair="out", flow="-200"),
        )
    )
    assert all(value.growth == value.wealth == 1 and value.drawdown == 0 for value in values)


def test_no_flow_drawdown_uses_running_wealth_peak() -> None:
    values = derive_wealth_path(
        (
            point(0, "1000", role="baseline"),
            point(1, "1200"),
            point(2, "900"),
            point(3, "990"),
        )
    )
    assert values[2].wealth == Decimal("0.9")
    assert values[2].drawdown == Decimal("0.25")
    assert values[3].drawdown == Decimal("0.175")


@pytest.mark.parametrize("nav", [None, "0", "-1"])
def test_invalid_baseline_never_creates_a_return(nav: str | None) -> None:
    values = derive_wealth_path((point(0, nav, role="baseline"), point(1, "1000")))
    reason = "missing_valuation" if nav is None else "nonpositive_nav"
    assert values[0].reasons == (reason,)
    assert set(values[1].reasons) == {reason, "incomplete_return_path"}
    assert all(value.growth is value.wealth is value.drawdown is None for value in values)


@pytest.mark.parametrize(
    ("nav", "reasons", "expected"),
    [
        (None, (), "missing_valuation"),
        ("0", (), "nonpositive_nav"),
        ("-100", (), "nonpositive_nav"),
        ("1100", ("stale_mark",), "stale_mark"),
    ],
)
def test_missing_or_untrusted_valuation_latches_the_suffix(
    nav: str | None, reasons: tuple[str, ...], expected: str
) -> None:
    values = derive_wealth_path(
        (
            point(0, "1000", role="baseline"),
            point(1, nav, reasons=reasons),
            point(2, "1210"),
            point(3, "1331"),
        )
    )
    assert values[0].wealth == 1
    assert values[1].reasons == (expected,)
    for value in values[2:]:
        assert value.growth is value.wealth is value.drawdown is None
        assert set(value.reasons) == {expected, "incomplete_return_path"}


@pytest.mark.parametrize("missing_role", ["pre_flow", "post_flow"])
def test_unknown_flow_valuation_is_undefined_without_later_reconstruction(
    missing_role: str,
) -> None:
    values = derive_wealth_path(
        (
            point(0, "1000", role="baseline"),
            point(1, None if missing_role == "pre_flow" else "1100", role="pre_flow", pair="f"),
            point(
                2,
                None if missing_role == "post_flow" else "1600",
                role="post_flow",
                pair="f",
                flow="500",
            ),
            point(3, "1760"),
        )
    )
    assert values[-1].wealth is None
    assert f"missing_{missing_role}_valuation" in values[-1].reasons
    assert "incomplete_return_path" in values[-1].reasons


def test_full_withdrawal_to_zero_invalidates_ratios_without_inventing_a_loss() -> None:
    values = derive_wealth_path(
        (
            point(0, "1000", role="baseline"),
            point(1, "1000", role="pre_flow", pair="f"),
            point(2, "0", role="post_flow", pair="f", flow="-1000"),
            point(3, "1000"),
        )
    )
    assert values[2].wealth is values[2].drawdown is None
    assert values[2].reasons == ("nonpositive_nav",)
    assert values[3].wealth is None


@pytest.mark.parametrize(
    "rows",
    [
        (),
        (point(0, "1000"),),
        (point(0, "1000", role="baseline"), point(1, "1000", role="baseline")),
        (point(1, "1000", role="baseline"), point(0, "1000")),
        (point(0, "1000", role="baseline"), point(0, "1000")),
        (
            point(0, "1000", role="baseline"),
            replace(point(1, "1000"), point_id="point-0"),
        ),
        (point(0, "1000", role="baseline"), point(1, "1100", role="pre_flow", pair="a")),
        (point(0, "1000", role="baseline"), point(1, "1500", role="post_flow", pair="a")),
        (
            point(0, "1000", role="baseline"),
            point(1, "1100", role="pre_flow", pair="a"),
            point(2, "1600", role="post_flow", pair="b", flow="500"),
        ),
        (
            point(0, "1000", role="baseline"),
            point(1, "1100", role="pre_flow", pair="a"),
            point(2, "1601", role="post_flow", pair="a", flow="500"),
        ),
        (
            point(0, None, role="baseline"),
            point(1, "1100", role="pre_flow", pair="a"),
            point(2, "1601", role="post_flow", pair="a", flow="500"),
        ),
        (
            point(0, "1000", role="baseline"),
            point(1, "1100", role="pre_flow", pair="a"),
            point(2, "1150"),
            point(3, "1600", role="post_flow", pair="a", flow="500"),
        ),
        (
            point(0, "1000", role="baseline"),
            point(1, "1100", role="pre_flow", pair="a"),
            point(2, "1600", role="post_flow", pair="a", flow="500"),
            point(3, "1600", role="pre_flow", pair="a"),
            point(4, "1700", role="post_flow", pair="a", flow="100"),
        ),
    ],
)
def test_malformed_paths_reject_even_after_an_unknown_valuation(
    rows: tuple[WealthPoint, ...],
) -> None:
    with pytest.raises(ValueError):
        derive_wealth_path(rows)


@pytest.mark.parametrize(
    "changes",
    [
        {"nav": Decimal("NaN")},
        {"nav": Decimal("Infinity")},
        {"nav": Decimal("1E-1000000")},
        {"nav": Decimal("1E1000000")},
        {"nav": Decimal("1." + "2" * 64)},
        {"signed_flow": Decimal("0.00000000001")},
        {"signed_flow": Decimal("NaN")},
        {"signed_flow": Decimal(1)},
        {"flow_pair_id": "unpaired"},
        {"role": "unsupported"},
        {"role": "pre_flow"},
        {"sequence": True},
        {"sequence": -1},
        {"point_id": " "},
        {"reasons": ("",)},
    ],
)
def test_source_rows_reject_invalid_money_structure_and_identity(
    changes: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        replace(point(0, "1000", role="baseline"), **changes)


def test_rows_are_frozen_and_source_money_is_canonical_without_rounding() -> None:
    source = point(0, "1000.0000000000", role="baseline", reasons=("b", "a", "a"))
    assert source.nav == Decimal(1000)
    assert source.nav.as_tuple() == Decimal("1E+3").as_tuple()
    assert source.reasons == ("a", "b")
    with pytest.raises(FrozenInstanceError):
        source.nav = Decimal(1)  # type: ignore[misc]
    value = derive_wealth_path((point(0, "1000", role="baseline"),))[0]
    with pytest.raises(FrozenInstanceError):
        value.wealth = Decimal(2)  # type: ignore[misc]


def test_high_precision_analytical_benchmark_nav_is_not_money_quantized() -> None:
    nav = Decimal("1428." + "571428" * 10)
    with localcontext(derived_context()):
        before = nav * 2
        after = before + Decimal(1000)
        terminal = after * 2
    rows = (
        WealthPoint("baseline", 0, nav, role="baseline"),
        WealthPoint("before", 1, before, flow_pair_id="flow", role="pre_flow"),
        WealthPoint("after", 2, after, Decimal(1000), "flow", "post_flow"),
        WealthPoint("terminal", 3, terminal),
    )
    assert rows[0].nav == nav
    assert len(rows[0].nav.as_tuple().digits) == 64
    assert tuple(value.growth for value in derive_wealth_path(rows)) == (
        Decimal(1),
        Decimal(2),
        Decimal(1),
        Decimal(2),
    )
    assert derive_wealth_path(rows)[-1].wealth == Decimal(4)


@pytest.mark.parametrize("nav", ["1E-11", "1E18", "1E-999999", "1E999999"])
def test_nav_uses_derived_numeric_range_instead_of_persisted_money_range(nav: str) -> None:
    row = point(0, nav, role="baseline")
    assert row.nav == Decimal(nav)
    assert derive_wealth_path((row,))[0].wealth == 1


def test_analytical_post_flow_nav_uses_pinned_derived_addition() -> None:
    # 64 significant input digits; exact addition would need 65. The analytical
    # model rounds once under its declared context, without inventing a return.
    before = Decimal("999." + "9" * 61)
    rows = (
        WealthPoint("baseline", 0, before, role="baseline"),
        WealthPoint("before", 1, before, flow_pair_id="flow", role="pre_flow"),
        WealthPoint("after", 2, Decimal(1001), Decimal(1), "flow", "post_flow"),
    )
    with localcontext() as ambient:
        ambient.prec = 2
        ambient.traps[Inexact] = True
        assert derive_wealth_path(rows)[-1].wealth == 1


def test_path_requires_immutable_exact_rows() -> None:
    with pytest.raises(ValueError):
        derive_wealth_path([point(0, "1000", role="baseline")])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        derive_wealth_path((object(),))  # type: ignore[arg-type]


def test_derived_context_is_fresh_and_wealth_ignores_hostile_ambient_settings() -> None:
    rows = (
        point(0, "3", role="baseline"),
        point(1, "7"),
        point(2, "11"),
        point(3, "6"),
    )
    expected = derive_wealth_path(rows)
    assert expected[1].growth == Decimal("2." + "3" * 63)
    assert len(expected[1].growth.as_tuple().digits) == 64
    first = derived_context()
    first.prec = 2
    first.traps[Inexact] = True
    assert derived_context().prec == 64
    assert derived_context().rounding == ROUND_HALF_EVEN
    assert not derived_context().traps[Inexact]
    with localcontext() as ambient:
        ambient.prec = 2
        ambient.rounding = ROUND_DOWN
        ambient.Emin = -2
        ambient.Emax = 2
        ambient.traps[Inexact] = True
        ambient.traps[Rounded] = True
        ambient.clear_flags()
        expected_flags = ambient.flags.copy()
        assert derive_wealth_path(rows) == expected
        assert ambient.prec == 2
        assert ambient.rounding == ROUND_DOWN
        assert ambient.flags == expected_flags


def test_flow_equality_uses_exact_source_values_under_hostile_ambient_precision() -> None:
    rows = (
        point(0, "99999999999999999.0000000001", role="baseline"),
        point(1, "99999999999999999.0000000001", role="pre_flow", pair="tiny"),
        point(
            2, "99999999999999999.0000000002", role="post_flow", pair="tiny", flow="0.0000000001"
        ),
    )
    with localcontext() as ambient:
        ambient.prec = 2
        ambient.traps[Inexact] = True
        assert derive_wealth_path(rows)[-1].wealth == 1
        with pytest.raises(ValueError, match="post-flow NAV"):
            derive_wealth_path((*rows[:-1], replace(rows[-1], nav=rows[1].nav)))


@pytest.mark.parametrize(
    ("growth", "wealth", "drawdown", "reasons"),
    [
        (None, None, None, ()),
        (None, Decimal(1), None, ("missing_valuation",)),
        (Decimal(1), Decimal(1), Decimal(0), ("stale_mark",)),
        (Decimal(0), Decimal(1), Decimal(0), ()),
        (Decimal(1), Decimal(1), Decimal("-0.1"), ()),
    ],
)
def test_output_values_reject_contradictory_defined_and_null_states(
    growth: Decimal | None,
    wealth: Decimal | None,
    drawdown: Decimal | None,
    reasons: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError):
        WealthValue("point", 0, growth, wealth, drawdown, reasons)
