"""Public fallback hooks observe class lifetime, bytes and failure traversal.

Fresh private Mapping classes have no test/global/closure strong reference after
their factory returns. An inherited hook swaps the instance to a layout-compatible
sibling; GC then collects the old class's MRO cycle. These are current public
serializer regressions, with no private implementation patch or timing claim.
"""

import gc
import weakref
from collections.abc import Mapping
from types import SimpleNamespace

import pytest

from packages.domain import canonical

MAPPING_BYTES = (
    b'{"type":"mapping","value":['
    b'{"key":{"type":"string","value":"a"},"value":{"type":"int","value":"1"}},'
    b'{"key":{"type":"string","value":"z"},"value":{"type":"int","value":"2"}}]}'
)
NESTED_BYTES = (
    b'{"type":"tuple","value":[{"type":"bool","value":false},'
    b'{"type":"tuple","value":[{"type":"string","value":"left"},'
    + MAPPING_BYTES
    + b',{"type":"tuple","value":[{"type":"bytes","value":"01"},'
    b'{"type":"null","value":null}]}]},{"type":"int","value":"-2"}]}'
)
ALIAS_BYTES = (
    b'{"type":"tuple","value":['
    + MAPPING_BYTES
    + b',{"type":"string","value":"middle"},'
    + MAPPING_BYTES
    + b"]}"
)


class LayoutMapping(Mapping):
    """Both swapping classes inherit the same layout and the same hook."""

    def __init__(self, state):
        self.state = state

    def __getitem__(self, key):
        for name, value in self.state.rows:
            if name == key:
                return value
        raise KeyError(key)

    def __iter__(self):
        return (key for key, _value in self.state.rows)

    def __len__(self):
        return len(self.state.rows)

    def items(self):
        state = self.state
        # This inherited method has no closure or __class__ cell referencing the
        # private subclass, so its own frame does not retain that old class.
        self.__class__ = ReplacementMapping
        gc.collect()
        state.lifetimes.append((state.label, state.old_class_ref() is not None))
        state.events.append(state.label)
        state.visits += 1
        if state.error is not None and state.visits == state.raise_on_visit:
            raise state.error
        return state.rows


class ReplacementMapping(LayoutMapping):
    pass


def private_mapping(*, label="mapping", events=None, lifetimes=None, error=None, raise_on_visit=1):
    # After return, only the instance and normal MRO cycles retain this class;
    # the state holds a weak reference, and no test/global/closure holds the type.
    class DisappearingMapping(LayoutMapping):
        pass

    state = SimpleNamespace(
        rows=(("z", 2), ("a", 1)),
        label=label,
        events=[] if events is None else events,
        lifetimes=[] if lifetimes is None else lifetimes,
        visits=0,
        error=error,
        raise_on_visit=raise_on_visit,
        old_class_ref=weakref.ref(DisappearingMapping),
    )
    value = DisappearingMapping(state)
    return value, state.old_class_ref, state


def success_shape(form, value):
    if form == "scalar":
        return value, MAPPING_BYTES
    if form == "nested":
        return (False, ("left", value, (b"\x01", None)), -2), NESTED_BYTES
    assert form == "repeated-alias"
    return (value, "middle", value), ALIAS_BYTES


@pytest.mark.parametrize("form", ["scalar", "nested", "repeated-alias"])
def test_mapping_hook_releases_old_class_and_preserves_literal_canonical_bytes(form):
    value, old_class, state = private_mapping()
    root, expected = success_shape(form, value)

    assert canonical.canonical_json_bytes(root) == expected

    visits = 2 if form == "repeated-alias" else 1
    assert state.lifetimes == [("mapping", False)] * visits
    assert state.events == ["mapping"] * visits
    assert value.__class__ is ReplacementMapping
    gc.collect()
    assert old_class() is None


def failing_shape(form, error):
    events, lifetimes = [], []
    changing, _old, _state = private_mapping(
        label="changing",
        events=events,
        lifetimes=lifetimes,
        error=error,
        raise_on_visit=2 if form == "repeated-alias" else 1,
    )
    if form == "scalar":
        return changing, events, lifetimes, ["changing"]
    after, _after_old, _after_state = private_mapping(
        label="after", events=events, lifetimes=lifetimes
    )
    if form == "repeated-alias":
        return (
            (changing, "middle", changing, after),
            events,
            lifetimes,
            ["changing", "changing"],
        )
    assert form == "nested"
    before, _before_old, _before_state = private_mapping(
        label="before", events=events, lifetimes=lifetimes
    )
    return (before, ("middle", changing), after), events, lifetimes, ["before", "changing"]


@pytest.mark.parametrize("form", ["scalar", "nested", "repeated-alias"])
def test_mapping_hook_failure_preserves_identity_output_lifetime_and_traversal(form):
    error = RuntimeError("selected Mapping hook failure")
    cause, context = LookupError("existing cause"), IndexError("existing context")
    error.__cause__, error.__context__ = cause, context
    suppressed = error.__suppress_context__
    value, events, lifetimes, expected_events = failing_shape(form, error)
    untouched_output = object()
    output = untouched_output

    with pytest.raises(RuntimeError) as raised:
        output = canonical.canonical_json_bytes(value)

    assert raised.value is error
    assert raised.value.__cause__ is cause
    assert raised.value.__context__ is context
    assert raised.value.__suppress_context__ is suppressed
    assert output is untouched_output
    assert events == expected_events
    assert lifetimes == [(label, False) for label in expected_events]
