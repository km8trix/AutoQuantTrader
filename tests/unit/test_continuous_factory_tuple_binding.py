"""Exact tuple self-comparison never replaces mutable descendant validation."""

from dataclasses import dataclass

import pytest

import packages.persistence.continuous_integrity as integrity


@dataclass
class Node:
    value: object


@pytest.mark.parametrize("capture", ["original", "fresh"])
@pytest.mark.parametrize("descendant", ["list", "mapping", "dataclass"])
def test_tuple_self_binding_still_checks_mutable_descendants(capture, descendant):
    marker = object()
    child = (
        [marker]
        if descendant == "list"
        else {"key": marker}
        if descendant == "mapping"
        else Node(marker)
    )
    wrapped = (child,)
    old = integrity._factory_structure((wrapped if capture == "original" else (), (), {}))
    records = integrity._factory_structure((wrapped if capture == "fresh" else (),), original=old)
    tuple_record = next(record for record in records if record[1] is wrapped)
    assert tuple_record[0] == "sequence" and tuple_record[2] is tuple
    assert tuple_record[4] is wrapped
    integrity._require_factory_structure(records)
    if descendant == "list":
        child[0] = object()
    elif descendant == "mapping":
        child["key"] = object()
    else:
        child.value = object()
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_CHANGED"):
        integrity._require_factory_structure(records)


def test_tuple_aliases_and_cycle_still_check_the_shared_mutable_object():
    child = []
    wrapped = (child, child)
    child.append(wrapped)
    records = integrity._factory_structure((wrapped,))
    assert sum(record[1] is wrapped for record in records) == 1
    assert sum(record[1] is child for record in records) == 1
    integrity._require_factory_structure(records)
    child.append(object())
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_CHANGED"):
        integrity._require_factory_structure(records)


@pytest.mark.parametrize("parent_kind", ["list", "mapping", "dataclass"])
def test_equal_distinct_tuple_replacement_in_mutable_parent_is_rejected(parent_kind):
    original = (object(), object())
    replacement = tuple(list(original))
    assert replacement == original and replacement is not original
    parent = (
        [original]
        if parent_kind == "list"
        else {"key": original}
        if parent_kind == "mapping"
        else Node(original)
    )
    records = integrity._factory_structure((parent,))
    integrity._require_factory_structure(records)
    if parent_kind == "list":
        parent[0] = replacement
    elif parent_kind == "mapping":
        parent["key"] = replacement
    else:
        parent.value = replacement
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_CHANGED"):
        integrity._require_factory_structure(records)


@pytest.mark.parametrize("difference", ["none", "value", "length"])
def test_nonidentical_tuple_binding_keeps_original_comparison_fallback(difference):
    # Synthetic binding exercises fallback compatibility; constructors normally
    # retain the exact tuple as its own snapshot.
    original = (object(), object())
    values = tuple(list(original))
    assert values is not original
    if difference == "value":
        values = (original[0], object())
    elif difference == "length":
        values = original[:1]
    records = (("sequence", original, tuple, (), values),)
    if difference == "none":
        integrity._require_factory_structure(records)
    else:
        with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_CHANGED"):
            integrity._require_factory_structure(records)


def test_tuple_fast_path_does_not_skip_the_original_type_check():
    original = (object(),)
    records = (("sequence", original, list, (), original),)
    with pytest.raises(integrity.ContinuousIntegrityError, match="TYPE_CHANGED"):
        integrity._require_factory_structure(records)
