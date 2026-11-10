"""Finite old/new detachment compatibility; synthetic values grant no authority."""

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import date
from decimal import Decimal
from hashlib import sha256

import pytest

from packages.domain.canonical import canonical_json_bytes
from packages.persistence import detached_journal_capture as subject


def legacy_detached(value: object) -> object:
    """Literal original function, with only its recursive name substituted."""
    if type(value) is bytes:
        return ("bytes", len(value), sha256(value).hexdigest())
    if isinstance(value, Mapping):
        return tuple((str(key), legacy_detached(item)) for key, item in sorted(value.items()))
    if is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__qualname__,
            tuple(
                (f.name, legacy_detached(getattr(value, f.name)))
                for f in fields(value)
                if f.name not in {"_owner", "_validated_values"}
            ),
        )
    if type(value) is tuple:
        return tuple(legacy_detached(item) for item in value)
    return value


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        -5,
        2**80,
        "",
        "snowman:\u2603",
        b"",
        b"\x00\xff",
        (),
        ((1, False), ("x", None), b"payload"),
        {"z": (2, b"data"), "a": (Decimal("1.200"), date(2026, 9, 24))},
    ],
)
def test_exact_output_bytes_and_hash_match_literal_original(value: object) -> None:
    before = legacy_detached(value)
    after = subject.detached_journal_value(value)
    assert after == before
    assert canonical_json_bytes(after) == canonical_json_bytes(before)
    assert (
        sha256(canonical_json_bytes(after)).digest()
        == sha256(canonical_json_bytes(before)).digest()
    )


class Text(str):
    pass


class Number(int):
    pass


class Tuple(tuple):
    pass


class Bytes(bytes):
    pass


@pytest.mark.parametrize("value", [Text("text"), Number(4), Tuple((1,)), Bytes(b"data")])
def test_subclasses_keep_original_passthrough_identity(value: object) -> None:
    assert legacy_detached(value) is value
    assert subject.detached_journal_value(value) is value


@dataclass(frozen=True)
class TextRecord(str):
    value: str


@dataclass(frozen=True)
class NumberRecord(int):
    value: int


@dataclass(frozen=True)
class TupleRecord(tuple):
    value: tuple


@pytest.mark.parametrize("value", [TextRecord("text"), NumberRecord(7), TupleRecord((1, "x"))])
def test_dataclass_builtin_subclasses_keep_reflected_record_behavior(value: object) -> None:
    expected = legacy_detached(value)
    assert expected == (type(value).__qualname__, (("value", value.value),))
    assert subject.detached_journal_value(value) == expected
    assert canonical_json_bytes(subject.detached_journal_value(value)) == canonical_json_bytes(
        expected
    )


def test_dataclass_field_read_order_and_excluded_fields_are_unchanged() -> None:
    events = []

    @dataclass
    class Record:
        first: object
        _owner: object
        second: object
        _validated_values: object

        def __getattribute__(self, name: str) -> object:
            if name in ("first", "_owner", "second", "_validated_values"):
                events.append(name)
            return object.__getattribute__(self, name)

    value = Record((1, b"payload"), object(), {"b": False, "a": None}, object())
    before = legacy_detached(value)
    old_events = events[:]
    events.clear()
    assert subject.detached_journal_value(value) == before
    assert events == old_events == ["first", "second"]
    assert subject.detached_journal_value(Record) is Record


def test_mapping_items_key_conversion_and_nested_field_hooks_keep_order() -> None:
    events = []

    class Key:
        def __init__(self, order: int) -> None:
            self.order = order

        def __lt__(self, other: "Key") -> bool:
            events.append(("compare", self.order, other.order))
            return self.order < other.order

        def __str__(self) -> str:
            events.append(("string", self.order))
            return str(self.order)

    class View(Mapping):
        def __iter__(self):
            raise AssertionError("custom items path required")

        def __len__(self):
            return 2

        def __getitem__(self, key):
            raise AssertionError("custom items path required")

        def items(self):
            events.append(("items",))
            return [(Key(2), (False, b"two")), (Key(1), (None, b"one"))]

    value = View()
    before = legacy_detached(value)
    old_events = events[:]
    events.clear()
    assert subject.detached_journal_value(value) == before
    assert events == old_events


@pytest.mark.parametrize("value", [None, True, 7, "text", (), b"bytes"])
def test_mapping_classification_precedes_exact_builtin_dispatch(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    events = []

    class Classifier(type):
        def __instancecheck__(cls, instance: object) -> bool:
            events.append(type(instance).__name__)
            return True

    class ClassifiedMapping(metaclass=Classifier):
        pass

    monkeypatch.setattr(subject, "Mapping", ClassifiedMapping)
    monkeypatch.setitem(globals(), "Mapping", ClassifiedMapping)

    def outcome(function):
        try:
            return ("result", function(value))
        except AttributeError as error:
            return ("error", type(error), str(error))

    before = outcome(legacy_detached)
    old_events = events[:]
    events.clear()
    assert outcome(subject.detached_journal_value) == before
    assert events == old_events
    assert events == ([] if type(value) is bytes else [type(value).__name__])


def test_custom_metaclass_reflection_keeps_fallback_order() -> None:
    events = []

    class Metadata(type):
        def __getattribute__(cls, name: str) -> object:
            if name == "__dataclass_fields__":
                events.append(name)
            return super().__getattribute__(name)

    class Other(metaclass=Metadata):
        pass

    value = Other()
    assert legacy_detached(value) is value
    old_events = events[:]
    events.clear()
    assert subject.detached_journal_value(value) is value
    assert events == old_events


@pytest.mark.parametrize("mode", ["items", "field", "sort"])
def test_fallback_errors_and_preceding_hooks_match(mode: str) -> None:
    events = []

    class BrokenMapping(dict):
        def items(self):
            events.append("items")
            raise ValueError("synthetic items failure")

    @dataclass
    class BrokenRecord:
        field: int

        def __getattribute__(self, name: str) -> object:
            if name == "field":
                events.append("field")
                raise ValueError("synthetic field failure")
            return object.__getattribute__(self, name)

    value = {"items": BrokenMapping(), "field": BrokenRecord(1), "sort": {1: 0, "x": 0}}[mode]
    outcomes = []
    for function in (legacy_detached, subject.detached_journal_value):
        events.clear()
        with pytest.raises((ValueError, TypeError)) as error:
            function(value)
        outcomes.append((type(error.value), str(error.value), events[:]))
    assert outcomes[0] == outcomes[1]


def test_every_bytes_occurrence_is_still_hashed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    original_sha256 = sha256

    def tracked(payload: bytes):
        calls.append(payload)
        return original_sha256(payload)

    monkeypatch.setattr(subject, "sha256", tracked)
    monkeypatch.setitem(globals(), "sha256", tracked)
    shared = b"same"
    value = (shared, {"a": shared}, shared)
    before = legacy_detached(value)
    old_calls = calls[:]
    calls.clear()
    assert subject.detached_journal_value(value) == before
    assert calls == old_calls == [shared, shared, shared]


def test_mutation_between_calls_is_observed_without_cache() -> None:
    @dataclass
    class Mutable:
        value: object

    value = Mutable({"item": (1, b"old")})
    before = subject.detached_journal_value(value)
    value.value["item"] = (2, b"new")
    after = subject.detached_journal_value(value)
    assert before != after
    assert after == legacy_detached(value)


def test_nested_finite_graph_retains_every_occurrence() -> None:
    value = (1, "leaf", b"payload")
    for _ in range(64):
        value = (value, False)
    assert subject.detached_journal_value(value) == legacy_detached(value)
