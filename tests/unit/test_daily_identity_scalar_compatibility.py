"""Identity-sequence and read-order compatibility for immutable scalar leaves.

The oracle is the literal prior traversal. Exact built-in leaves have no graph
children; scalar subclasses, dataclasses and mappings retain the original path.
"""

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from types import MappingProxyType

import pytest

from packages.persistence.daily_runtime_risk import SqlDailyRuntimeRisk


def legacy_fields(value):
    pending, seen = [value], set()
    retained = []
    while pending:
        item = pending.pop()
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


@dataclass
class Node:
    payload: object
    nested: object = None


@dataclass
class StringRecord(str):
    payload: object


def assert_same_identities(value):
    old = legacy_fields(value)
    new = SqlDailyRuntimeRisk._assignment_identity_fields(value)
    assert len(new) == len(old)
    assert all(a is b for a, b in zip(old, new, strict=True))
    return new


@pytest.mark.parametrize(
    "leaf",
    [
        None,
        True,
        17,
        "original",
        b"raw",
        Decimal("2.30"),
        date(2026, 9, 13),
        datetime(2026, 9, 13, tzinfo=UTC),
        object(),
    ],
)
def test_scalar_identity_remains_in_its_parent_fields(leaf):
    assert assert_same_identities(leaf) == ()
    result = assert_same_identities(Node(leaf))
    assert result[0] is leaf


def test_aliases_cycles_order_and_scalar_subclass_children_are_preserved():
    root = Node(None)
    child = Node(StringRecord(root))
    rows = {"root": root, "child": child, "aliases": (child, child)}
    root.payload = (MappingProxyType(rows), child)
    values = assert_same_identities(root)
    assert any(item is child.payload for item in values)
    assert any(item is root for item in values)
    assert_same_identities((root, root, rows))


def test_replaced_nested_field_is_still_read_on_every_call():
    leaf = Node("original")
    value = Node((leaf,))
    before = assert_same_identities(value)
    leaf.payload = "changed"
    after = assert_same_identities(value)
    assert any(a is not b for a, b in zip(before, after, strict=True))


@pytest.mark.parametrize("failure", [False, True])
def test_original_field_and_mapping_read_order_and_errors_remain(failure):
    trace = []

    class TracedMapping(dict):
        def items(self):
            trace.append("mapping.items")
            if failure:
                raise ValueError("original mapping fault")
            return super().items()

    @dataclass
    class TracedRecord:
        payload: object
        sibling: object

        def __getattribute__(self, name):
            if name in {"payload", "sibling"}:
                trace.append(name)
            return object.__getattribute__(self, name)

    value = TracedRecord(TracedMapping(row=Node("row")), ("same", "same"))

    def observe(function):
        trace.clear()
        try:
            result = function(value)
        except ValueError as error:
            return (type(error), str(error)), tuple(trace)
        return tuple(id(item) for item in result), tuple(trace)

    assert observe(SqlDailyRuntimeRisk._assignment_identity_fields) == observe(legacy_fields)
