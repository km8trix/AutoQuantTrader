"""Compatibility of tuple dispatch with the original complete identity traversal.

The literal pre-change oracle includes the existing exact-scalar exclusions.
Assertions compare object identities, mutation visibility, hook order and errors.
"""

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from types import MappingProxyType

import pytest

from packages.persistence.daily_runtime_risk import SqlDailyRuntimeRisk


def _prior_fields(value):
    pending, seen = [value], set()
    retained = []
    while pending:
        item = pending.pop()
        item_type = type(item)
        if (
            item_type is str
            or item_type is int
            or item_type is bytes
            or item_type is type(None)
            or item_type is bool
            or item_type is Decimal
            or item_type is datetime
            or item_type is date
            or item_type is object
        ):
            continue
        if id(item) in seen:
            continue
        seen.add(id(item))
        if is_dataclass(item) and not isinstance(item, type):
            nested = tuple(getattr(item, f.name) for f in fields(item))
        elif type(item) is tuple:
            nested = item
        elif isinstance(item, Mapping):
            nested = tuple(v for pair in item.items() for v in pair)
        else:
            continue
        retained.extend(nested)
        pending.extend(nested)
    return tuple(retained)


def _observe(function, value, trace):
    trace.clear()
    try:
        result = function(value)
    except Exception as error:
        cause = error.__cause__
        return (
            "error",
            type(error),
            str(error),
            None if cause is None else (type(cause), str(cause)),
            tuple(trace),
        )
    return "identities", tuple(id(item) for item in result), tuple(trace)


def _assert_equivalent(value, trace=None, reset=None):
    if trace is None:
        trace = []
    if reset is not None:
        reset()
    expected = _observe(_prior_fields, value, trace)
    if reset is not None:
        reset()
    actual = _observe(SqlDailyRuntimeRisk._assignment_identity_fields, value, trace)
    assert actual == expected
    return actual


@dataclass
class _Record:
    first: object
    second: object = None


@pytest.mark.parametrize(
    "leaf",
    [
        None,
        True,
        17,
        "original",
        b"raw",
        Decimal("2.30"),
        date(2026, 9, 25),
        datetime(2026, 9, 25, tzinfo=UTC),
        object(),
        1.25,
    ],
)
def test_nested_tuples_retain_every_parent_field_identity(leaf):
    child = _Record(leaf)
    value = ((), (leaf, child), child)
    result = _assert_equivalent(value)
    assert result[0] == "identities"
    assert id(leaf) in result[1]
    assert id(child) in result[1]


def test_tuple_aliases_and_cycles_keep_original_reverse_pending_order():
    rows = {}
    shared = _Record("shared")
    root = (shared, MappingProxyType(rows), shared)
    rows.update(root=root, repeated=(root, root), child=shared)
    _assert_equivalent(root)


def test_nested_replacement_is_read_again_without_cached_values():
    before, after = object(), object()
    child = _Record(before)
    root = ((child,), (child,))
    original = _assert_equivalent(root)
    child.first = after
    changed = _assert_equivalent(root)
    assert original != changed
    assert id(before) in original[1]
    assert id(after) in changed[1]


class _PlainTuple(tuple):
    pass


@dataclass
class _DataclassTuple(tuple):
    first: object


class _MappingTuple(tuple, Mapping):
    def items(self):
        return (("child", self[0]),)


@dataclass
class _DataclassMappingTuple(tuple, Mapping):
    first: object

    def items(self):
        raise AssertionError("dataclass precedence must remain")


@pytest.mark.parametrize(
    "kind", [_PlainTuple, _DataclassTuple, _MappingTuple, _DataclassMappingTuple]
)
def test_tuple_subclasses_keep_dataclass_and_mapping_precedence(kind):
    leaf = object()
    child = _Record(leaf)
    subclass = kind((child,))
    result = _assert_equivalent((subclass,))
    assert (id(leaf) in result[1]) is (kind is not _PlainTuple)


@pytest.mark.parametrize("fault", [None, "first", "second", "mapping"])
def test_hooks_and_exception_causes_keep_original_order(fault):
    trace = []

    class TracedMapping(dict):
        def items(self):
            trace.append("mapping")
            if fault == "mapping":
                raise ValueError("mapping failed") from LookupError("original cause")
            return super().items()

    @dataclass
    class TracedRecord:
        first: object
        second: object

        def __getattribute__(self, name):
            if name in {"first", "second"}:
                trace.append(name)
                if fault == name:
                    raise RuntimeError(name + " failed") from ValueError("original cause")
            return object.__getattribute__(self, name)

    root = ((TracedRecord(TracedMapping(child=_Record("leaf")), ("sibling",)),),)
    _assert_equivalent(root, trace)


@pytest.mark.parametrize("raise_lookup", [False, True])
def test_tuple_subclass_dataclass_discovery_remains_observable(raise_lookup):
    trace = []

    class ObservedType(type):
        def __getattribute__(cls, name):
            if name == "__dataclass_fields__":
                trace.append(name)
                if raise_lookup:
                    raise RuntimeError("class discovery failed")
            return super().__getattribute__(name)

    class ObservedTuple(tuple, metaclass=ObservedType):
        pass

    _assert_equivalent((ObservedTuple((_Record("leaf"),)),), trace)
    assert trace == ["__dataclass_fields__"]


@pytest.mark.parametrize("mutate", [False, True])
def test_mapping_hook_mutation_is_seen_by_later_tuple_child(mutate):
    trace = []
    before, after = object(), object()
    child = _Record(before)

    class MutatingMapping(dict):
        def items(self):
            trace.append("mapping")
            if mutate:
                child.first = after
            return super().items()

    mapping = MutatingMapping(child=child)
    root = (child, (mapping,))

    def reset():
        child.first = before

    result = _assert_equivalent(root, trace, reset)
    assert id(after if mutate else before) in result[1]


def test_identity_scan_does_not_call_user_hash_or_equality():
    @dataclass(eq=False)
    class IdentityOnly:
        value: object

        def __eq__(self, other):
            raise AssertionError("no equality dispatch")

        def __hash__(self):
            raise AssertionError("no hash dispatch")

    record = IdentityOnly(object())
    _assert_equivalent(((record, record), record))
