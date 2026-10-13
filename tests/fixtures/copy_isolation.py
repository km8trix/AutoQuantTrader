"""Isolate stdlib class-cache side effects in original-owner copy tests."""

from copy import copy


def copy_preserving_class_inventory(value):
    """Copy the object without retaining stdlib's lazy class slot cache."""
    kind = type(value)
    missing = object()
    original = vars(kind).get("__slotnames__", missing)
    try:
        return copy(value)
    finally:
        current = vars(kind).get("__slotnames__", missing)
        if current is not original:
            if original is missing:
                delattr(kind, "__slotnames__")
            else:
                kind.__slotnames__ = original
