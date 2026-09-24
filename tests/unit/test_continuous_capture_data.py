"""Finite exact-data comparison profile; no store ownership is inferred here."""

from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from types import MappingProxyType

import pytest
from sqlalchemy.sql.elements import quoted_name

from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.durable_journal_contracts import JournalKey
from packages.domain.models import Side
from packages.domain.personal_contracts import CausalMark, VersionPin
from packages.domain.research_dataset import ResearchCalendar, ResearchSession
from packages.persistence import continuous_capture_comparison as comparison_module
from packages.persistence.continuous_capture_comparison import (
    ContinuousCaptureComparison,
    ContinuousCaptureComparisonError,
)
from packages.persistence.durable_journal import JournalReadSnapshot


def compare(left, right):
    return ContinuousCaptureComparison().data(left, right)


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        4,
        "original",
        b"retained",
        Decimal("1.00"),
        date(2026, 9, 13),
        datetime(2026, 9, 13, tzinfo=UTC),
        datetime(2026, 9, 13),
        timedelta(seconds=1),
        Side.BUY,
    ],
)
def test_exact_scalar_profile(value):
    assert compare(value, value) is None


@pytest.mark.parametrize(
    "left,right",
    [
        (True, 1),
        (1, Decimal(1)),
        ("x", b"x"),
        (Decimal("1.0"), Decimal("1.00")),
        (date(2026, 9, 13), datetime(2026, 9, 13)),
        (Side.BUY, "buy"),
        (datetime(2026, 9, 13), datetime(2026, 9, 13, tzinfo=UTC)),
        (datetime(2026, 9, 13), datetime(2026, 9, 13, fold=1)),
    ],
)
def test_equal_coercions_and_representation_changes_are_denied(left, right):
    with pytest.raises(ContinuousCaptureComparisonError):
        compare(left, right)


def test_complete_declared_contract_and_legacy_data_fields_without_hash(monkeypatch):
    at = datetime(2026, 9, 14, 13, 30, tzinfo=UTC)
    calendar = ResearchCalendar(
        "original",
        "1",
        "XNYS",
        "America/New_York",
        (ResearchSession("XNYS", at.date(), at, at + timedelta(hours=6, minutes=30), "regular"),),
    )
    key = JournalKey("capture", "original", "account", "fixture", "synthetic", "a" * 64)
    mark = CausalMark("mark", "instrument", "SPY", Decimal(10), at.date(), at, at, "a" * 64)
    old = (VersionPin("original", "1", "a" * 64), calendar, ReferenceConfiguration(), key, mark)
    fresh = tuple(replace(item) for item in old)

    def forbidden(_self):
        pytest.fail("data comparison requested a semantic hash")

    monkeypatch.setattr(VersionPin, "semantic_sha256", property(forbidden))
    assert compare(old, fresh) is None
    changed = (*fresh[:-1], replace(mark, quality="unavailable"))
    with pytest.raises(ContinuousCaptureComparisonError):
        compare(old, changed)


def test_exact_ordered_complete_rows_and_aliases_are_compared_each_call():
    shared = {"payload": b"old", "counter": 1}
    old = (MappingProxyType(shared),) * 2
    fresh = (MappingProxyType(dict(shared)), MappingProxyType(dict(shared)))
    comparison = ContinuousCaptureComparison()
    comparison.data(old, fresh)
    shared["payload"] = b"new"
    with pytest.raises(ContinuousCaptureComparisonError):
        comparison.data(old, fresh)
    shared["payload"] = b"old"
    comparison.data(old, fresh)
    for changed in (
        {"counter": 1, "payload": b"old"},
        {"payload": b"old"},
        {"payload": b"old", "counter": True},
        {1: b"old", "counter": 1},
    ):
        with pytest.raises(ContinuousCaptureComparisonError):
            compare(old[0], MappingProxyType(changed))


def test_opaque_tokens_subclasses_and_equality_hooks_are_not_data():
    calls = []

    @dataclass(frozen=True)
    class Unknown:
        value: int = 1

        def __eq__(self, _other):
            calls.append("arbitrary equality")
            return True

    class Text(str):
        def __eq__(self, _other):
            calls.append("string subclass equality")
            return True

    key = JournalKey("capture", "original", "account", "fixture", "synthetic", "a" * 64)
    raw = JournalReadSnapshot(key, None, None, None, None, None, False, False, object())
    for left, right in ((Unknown(), Unknown()), (Text("x"), Text("x")), (raw, raw), ([], [])):
        with pytest.raises(ContinuousCaptureComparisonError, match="DATA_PROFILE"):
            compare(left, right)
    assert calls == []


def test_only_exact_original_sql_name_keys_have_the_narrow_quote_profile():
    left = MappingProxyType({quoted_name("payload", None): b"retained"})
    assert compare(left, MappingProxyType({quoted_name("payload", None): b"retained"})) is None
    for key in (
        "payload",
        quoted_name("other", None),
        quoted_name("payload", True),
        quoted_name("payload", False),
        quoted_name("payload", 1),
    ):
        with pytest.raises(ContinuousCaptureComparisonError):
            compare(left, MappingProxyType({key: b"retained"}))
    with pytest.raises(ContinuousCaptureComparisonError, match="DATA_PROFILE"):
        compare(quoted_name("payload", None), quoted_name("payload", None))
    invalid = quoted_name("payload", 1)
    with pytest.raises(ContinuousCaptureComparisonError, match="ROW_QUOTE"):
        compare(MappingProxyType({invalid: b"retained"}), MappingProxyType({invalid: b"retained"}))
    calls = []

    class Key(str):
        __hash__ = str.__hash__

        def __eq__(self, other):
            calls.append(other)
            return True

    with pytest.raises(ContinuousCaptureComparisonError, match="ROW_KEYS"):
        compare(MappingProxyType({Key("payload"): 1}), MappingProxyType({Key("payload"): 1}))
    assert calls == []


def test_cycle_rejected_and_alias_bindings_remain_bounded(monkeypatch):
    left, right = {}, {}
    left["self"], right["self"] = left, right
    with pytest.raises(ContinuousCaptureComparisonError, match="CYCLE"):
        compare(left, right)
    monkeypatch.setattr(comparison_module, "MAX_CAPTURE_COMPARISON_BINDINGS", 5)
    repeated = ((),) * 5
    with pytest.raises(ContinuousCaptureComparisonError, match="BOUND"):
        compare(repeated, repeated)


def test_field_cap_precedes_materializing_field_inventory(monkeypatch):
    value = VersionPin("original", "1", "a" * 64)
    monkeypatch.setattr(comparison_module, "MAX_CAPTURE_COMPARISON_BINDINGS", 2)
    monkeypatch.setattr(
        comparison_module, "fields", lambda _value: pytest.fail("fields before cap")
    )
    with pytest.raises(ContinuousCaptureComparisonError, match="BOUND"):
        compare(value, value)


def test_pairs_preflight_and_cumulative_budget_and_identity(monkeypatch):
    comparison = ContinuousCaptureComparison()
    marker = object()
    comparison.identity(marker, marker)
    with pytest.raises(ContinuousCaptureComparisonError, match="IDENTITY"):
        comparison.identity(marker, object())
    assert list(comparison.pairs((1, 2), (3, 4))) == [(1, 3), (2, 4)]
    with pytest.raises(ContinuousCaptureComparisonError, match="TUPLE"):
        comparison.pairs([1], (1,))
    monkeypatch.setattr(comparison_module, "MAX_CAPTURE_COMPARISON_BINDINGS", comparison.bindings)
    with pytest.raises(ContinuousCaptureComparisonError, match="BOUND"):
        comparison.pairs((marker,), (marker,))
