"""Exact primitive admission preserves the original contract validator's behavior."""

from __future__ import annotations

import types
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from decimal import Decimal
from enum import IntEnum, StrEnum
from typing import ClassVar, Literal, TypeAliasType, Union, get_args, get_origin

import pytest

from packages.domain import personal_contracts as contracts

type _CountAlias = int
type _MaybeText = str | None


def _original_require_utc(value, name):
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise ValueError(f"{name} requires an aware UTC datetime")


def _original_check_type(value, annotation, name):
    # Literal pre-fast-path implementation; recursive calls stay in this oracle.
    if isinstance(annotation, TypeAliasType):
        _original_check_type(value, annotation.__value__, name)
        return
    origin, args = get_origin(annotation), get_args(annotation)
    if origin in (types.UnionType, Union):
        for candidate in args:
            try:
                _original_check_type(value, candidate, name)
                return
            except (TypeError, ValueError):
                pass
        raise ValueError(f"{name} has an unsupported value type")
    if origin is Literal:
        if not any(type(value) is type(v) and value == v for v in args):
            raise ValueError(f"{name} has an unsupported literal")
        return
    if origin is tuple:
        if type(value) is not tuple:
            raise ValueError(f"{name} must be immutable tuple")
        if len(args) == 2 and args[1] is Ellipsis:
            for item in value:
                _original_check_type(item, args[0], name)
        elif len(value) == len(args):
            for item, expected in zip(value, args, strict=True):
                _original_check_type(item, expected, name)
        else:
            raise ValueError(f"{name} tuple shape differs")
        return
    if annotation is type(None):
        if value is not None:
            raise ValueError(f"{name} must be null")
        return
    if not isinstance(annotation, type) or type(value) is not annotation:
        raise ValueError(f"{name} has an unsupported value type")
    if type(value) is Decimal and not value.is_finite():
        raise ValueError(f"{name} must be finite")
    if type(value) is datetime:
        _original_require_utc(value, name)
    if type(value) is str and len(value) > 65536:
        raise ValueError(f"{name} exceeds text bound")


def _exception_shape(error):
    if error is None:
        return None
    return (
        type(error),
        error.args,
        _exception_shape(error.__cause__),
        _exception_shape(error.__context__),
        error.__suppress_context__,
    )


def _outcome(check, value, annotation, name="field"):
    try:
        check(value, annotation, name)
    except BaseException as error:
        return _exception_shape(error)
    return None


class _Text(str):
    pass


class _Count(int):
    pass


class _Word(StrEnum):
    HALTED = "halted"


class _Rank(IntEnum):
    FIRST = 1


@pytest.mark.parametrize(
    ("value", "annotation"),
    [
        (None, type(None)),
        (False, bool),
        (True, bool),
        (0, int),
        (-17, int),
        (10**5000, int),
        ("", str),
        ("\N{GREEK SMALL LETTER PI}\x00\ud800", str),
        (_Text("x"), _Text),
        (_Count(1), _Count),
        (_Word.HALTED, _Word),
        (_Rank.FIRST, _Rank),
        (b"x", bytes),
    ],
    ids=[
        "none",
        "false",
        "true",
        "zero",
        "negative",
        "large-int",
        "empty",
        "unicode",
        "str-subclass",
        "int-subclass",
        "str-enum",
        "int-enum",
        "bytes-fallback",
    ],
)
def test_exact_values_and_declared_subclasses_match_literal_oracle(value, annotation):
    assert _outcome(_original_check_type, value, annotation) is None
    assert _outcome(contracts._check_type, value, annotation) is None


@pytest.mark.parametrize(
    ("value", "annotation", "message"),
    [
        (True, int, "has an unsupported value type"),
        (1, bool, "has an unsupported value type"),
        (None, str, "has an unsupported value type"),
        ("", type(None), "must be null"),
        (_Text("x"), str, "has an unsupported value type"),
        (_Count(1), int, "has an unsupported value type"),
        (_Word.HALTED, str, "has an unsupported value type"),
        (_Rank.FIRST, int, "has an unsupported value type"),
        ("x", _Text, "has an unsupported value type"),
        (1, _Count, "has an unsupported value type"),
    ],
)
def test_mismatches_preserve_exact_rejection_and_chaining(value, annotation, message):
    expected = _outcome(_original_check_type, value, annotation)
    assert expected == (ValueError, (f"field {message}",), None, None, False)
    assert _outcome(contracts._check_type, value, annotation) == expected


@pytest.mark.parametrize(
    ("value", "annotation", "valid"),
    [
        (7, _CountAlias, True),
        (True, _CountAlias, False),
        (None, _MaybeText, True),
        ("label", _MaybeText, True),
        (False, _MaybeText, False),
        (True, int | bool, True),
        (False, Union[str, int], False),  # noqa: UP007 - exercise the typing.Union fallback
        (True, Literal[True], True),
        (1, Literal[True], False),
        (False, Literal[0], False),
        ("plain", Literal["plain", "other"], True),
        ((7, False, "x", None), tuple[int, bool, str, type(None)], True),
        ((7, False, "x", None), tuple[int, bool, str, None], False),
        ((True, False, "x", None), tuple[int, bool, str, None], False),
        ((), tuple[int, ...], True),
        ((1, 2), tuple[int, ...], True),
        ((1, False), tuple[int, ...], False),
        ([1], tuple[int, ...], False),
        ((1,), tuple[int, bool], False),
        (((1, True), (2, False)), tuple[tuple[_CountAlias, bool], ...], True),
        (((1, True), (False, False)), tuple[tuple[_CountAlias, bool], ...], False),
    ],
)
def test_alias_union_literal_and_tuple_recursion_remain_original(value, annotation, valid):
    expected = _outcome(_original_check_type, value, annotation)
    assert (expected is None) is valid
    assert _outcome(contracts._check_type, value, annotation) == expected


@pytest.mark.parametrize("character", ["x", "\N{GRINNING FACE}"])
@pytest.mark.parametrize("length", [65535, 65536, 65537])
def test_text_bound_counts_characters_and_keeps_original_exception(character, length):
    value = character * length
    expected = _outcome(_original_check_type, value, str)
    assert (expected is None) is (length <= 65536)
    assert _outcome(contracts._check_type, value, str) == expected


def test_declared_string_subclass_keeps_original_bound_behavior():
    value = _Text("x" * 65537)
    assert _outcome(_original_check_type, value, _Text) is None
    assert _outcome(contracts._check_type, value, _Text) is None
    assert _outcome(contracts._check_type, value, str) == _outcome(_original_check_type, value, str)


def test_annotation_metaclass_is_compared_by_identity_without_equality():
    events = []

    class ObservedType(type):
        def __getattribute__(cls, name):
            if name == "__class__":
                events.append("annotation.__class__")
            return super().__getattribute__(name)

        def __eq__(cls, other):
            raise AssertionError("annotation equality must not run")

        __hash__ = type.__hash__

    class Record(metaclass=ObservedType):
        pass

    value = Record()
    expected = _outcome(_original_check_type, value, Record)
    original_events = events[:]
    events.clear()
    assert _outcome(contracts._check_type, value, Record) == expected is None
    assert events == original_events


@pytest.mark.parametrize("nested", [False, True])
def test_fallback_annotation_reflection_keeps_original_error_identity(nested):
    sentinel = StopIteration("reflection stopped")
    events = []

    class Annotation:
        @property
        def __class__(self):
            events.append("annotation.__class__")
            raise sentinel

    annotation = Annotation()
    if nested:
        annotation = tuple[annotation]
    value = (1,) if nested else 1
    for check in (_original_check_type, contracts._check_type):
        events.clear()
        with pytest.raises(StopIteration) as caught:
            check(value, annotation, "field")
        assert caught.value is sentinel
        assert events == ["annotation.__class__"]


@pytest.mark.parametrize(
    "value,annotation", [(None, type(None)), (True, bool), (2, int), ("", str)]
)
def test_success_does_not_format_name(value, annotation):
    class Name:
        def __format__(self, spec):
            raise AssertionError("successful validation must not format its name")

    for check in (_original_check_type, contracts._check_type):
        assert check(value, annotation, Name()) is None


@pytest.mark.parametrize("error_type", [ValueError, TypeError, StopIteration])
@pytest.mark.parametrize("annotation", [str, str | None])
def test_oversized_text_preserves_name_format_order_and_error_identity(error_type, annotation):
    traces = []
    outcomes = []

    def run(check):
        events = []
        sentinel = error_type("name format failed")

        class Name:
            def __format__(self, spec):
                events.append(("format", spec))
                raise sentinel

        with pytest.raises(error_type) as caught:
            check("x" * 65537, annotation, Name())
        assert caught.value is sentinel
        traces.append(events)
        outcomes.append(_exception_shape(caught.value))

    run(_original_check_type)
    run(contracts._check_type)
    assert traces[0] == traces[1]
    assert traces[0] == [("format", "")] * (
        3 if annotation is not str and error_type is not StopIteration else 1
    )
    assert outcomes[0] == outcomes[1]


def test_oversized_text_formats_name_once_and_preserves_active_exception_context():
    def run(check):
        events = []

        class Name:
            def __format__(self, spec):
                events.append(spec)
                return "named field"

        outer = LookupError("outer error")
        try:
            raise outer
        except LookupError:
            with pytest.raises(ValueError) as caught:
                check("x" * 65537, str, Name())
        assert caught.value.args == ("named field exceeds text bound",)
        assert caught.value.__context__ is outer
        assert caught.value.__cause__ is None
        assert caught.value.__suppress_context__ is False
        assert events == [""]

    run(_original_check_type)
    run(contracts._check_type)


@pytest.mark.parametrize("error_type", [ValueError, TypeError, StopIteration])
def test_literal_comparison_keeps_generator_exception_chaining(error_type):
    def run(check):
        sentinel = error_type("literal comparison failed")
        events = []

        class Comparable(int):
            def __eq__(self, other):
                events.append("compare")
                raise sentinel

            __hash__ = int.__hash__

        value = Comparable(1)
        annotation = Literal[value]
        events.clear()
        with pytest.raises(RuntimeError if error_type is StopIteration else error_type) as caught:
            check(value, annotation, "field")
        if error_type is StopIteration:
            assert caught.value.__cause__ is sentinel
            assert caught.value.__context__ is sentinel
            assert caught.value.__suppress_context__ is True
        else:
            assert caught.value is sentinel
        return events, _exception_shape(caught.value)

    assert run(_original_check_type) == run(contracts._check_type)


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        (Decimal("1.25"), True),
        (Decimal("NaN"), False),
        (Decimal("sNaN"), False),
        (Decimal("Infinity"), False),
        (datetime(2026, 1, 1, tzinfo=UTC), True),
        (datetime(2026, 1, 1), False),
        (datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1))), False),
    ],
)
def test_decimal_and_datetime_finite_utc_guards_are_unchanged(value, valid):
    expected = _outcome(_original_check_type, value, type(value))
    assert (expected is None) is valid
    assert _outcome(contracts._check_type, value, type(value)) == expected


@pytest.mark.parametrize("raises", [False, True])
def test_datetime_timezone_callback_count_and_error_identity_are_unchanged(raises):
    outcomes = []

    def run(check):
        events = []
        sentinel = StopIteration("timezone stopped")

        class Zone(tzinfo):
            def utcoffset(self, value):
                events.append("utcoffset")
                if raises:
                    raise sentinel
                return timedelta(0)

        value = datetime(2026, 1, 1, tzinfo=Zone())
        if raises:
            with pytest.raises(StopIteration) as caught:
                check(value, datetime, "field")
            assert caught.value is sentinel
        else:
            assert check(value, datetime, "field") is None
        outcomes.append(events)

    run(_original_check_type)
    run(contracts._check_type)
    assert outcomes == [["utcoffset"], ["utcoffset"]]


@dataclass(frozen=True)
class _OrderedRecord(contracts.ContractRecord):
    count: int
    label: str
    events: ClassVar[list[str]] = []

    def __getattribute__(self, name):
        if name in ("count", "label"):
            type(self).events.append(name)
        return object.__getattribute__(self, name)

    def __post_init__(self):
        contracts.ContractRecord.__post_init__(self)
        self.events.append("custom constraint")
        if self.count < 0:
            raise ValueError("negative count")


@pytest.mark.parametrize(
    ("count", "label", "message", "events"),
    [
        (True, "x", "count has an unsupported value type", ["count"]),
        (1, 2, "label has an unsupported value type", ["count", "label"]),
        (-1, "x", "negative count", ["count", "label", "custom constraint", "count"]),
    ],
)
def test_contract_field_order_and_later_constraints_survive(
    count, label, message, events, monkeypatch
):
    monkeypatch.setattr(_OrderedRecord, "events", [])
    with pytest.raises(ValueError, match=message):
        _OrderedRecord(count, label)
    assert _OrderedRecord.events == events


def test_constructor_rechecks_types_and_constraints_each_time(monkeypatch):
    monkeypatch.setattr(_OrderedRecord, "events", [])
    first = _OrderedRecord(1, "x")
    second = _OrderedRecord(1, "x")
    assert first is not second
    assert _OrderedRecord.events == ["count", "label", "custom constraint", "count"] * 2


def test_field_getter_mutation_of_later_hint_is_observed(monkeypatch):
    @dataclass(frozen=True)
    class MutableHintRecord(contracts.ContractRecord):
        first: int
        second: int

        def __getattribute__(self, name):
            if name == "first":
                hints["second"] = bool
            return object.__getattribute__(self, name)

    hints = contracts._hints(MutableHintRecord)
    monkeypatch.setitem(contracts._TYPE_HINTS, MutableHintRecord, hints.copy())
    hints = contracts._TYPE_HINTS[MutableHintRecord]
    assert MutableHintRecord(1, True).second is True
    hints["second"] = int
    with pytest.raises(ValueError, match="second has an unsupported value type"):
        MutableHintRecord(1, 1)


def test_real_contract_semantic_constraints_remain_after_primitive_admission():
    with pytest.raises(ValueError, match="pin name requires bounded nonempty trimmed text"):
        contracts.VersionPin("", "v1", "a" * 64)
    with pytest.raises(ValueError, match="pin content requires a SHA-256 digest"):
        contracts.VersionPin("name", "v1", "wrong")
    with pytest.raises(ValueError, match="invalid engine reduction point"):
        contracts.ReductionPoint(0, 0, datetime(2026, 1, 1, tzinfo=UTC), 9)
