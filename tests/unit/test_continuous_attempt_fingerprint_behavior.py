"""Finite behavior inventory checks; these seals provide no factory authority."""

import json
import os
import subprocess
import sys
from copy import copy
from pathlib import Path
from textwrap import dedent

import pytest
from sqlalchemy.sql.elements import quoted_name

from packages.persistence import _factory_attempt_behavior as behavior

pytestmark = pytest.mark.skipif(
    sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 12, 13),
    reason="finite implementation inventory belongs to the qualified CPython 3.12.13 proof",
)

_BEHAVIOR_GLOBAL = "original"


def declared(value="default", *, suffix="suffix"):
    return _BEHAVIOR_GLOBAL + str(value) + suffix


class DeclaredClass:
    __slots__ = ("value",)


def capture(*, functions=(declared,), classes=()):
    return behavior._capture_attempt_behavior(functions=functions, modules=(), classes=classes)


def test_original_declared_behavior_can_be_checked_repeatedly_without_execution():
    binding = capture(classes=(DeclaredClass,))
    assert binding.containers > 0 and binding.bindings > 0
    assert binding.require() is None
    assert binding.require() is None


@pytest.mark.parametrize("attribute", ["__code__", "__defaults__", "__kwdefaults__"])
def test_original_function_behavior_fields_cannot_be_replaced(monkeypatch, attribute):
    binding = capture()

    def forbidden(value="default", *, suffix="suffix"):
        raise AssertionError("substituted declared function executed")

    replacement = {
        "__code__": forbidden.__code__,
        "__defaults__": ("changed",),
        "__kwdefaults__": {"suffix": "changed"},
    }[attribute]
    monkeypatch.setattr(declared, attribute, replacement)
    with pytest.raises(behavior._AttemptBehaviorChanged):
        binding.require()


def test_keyword_default_dictionary_content_is_not_blessed_by_original_identity(monkeypatch):
    binding = capture()
    original = declared.__kwdefaults__
    monkeypatch.setitem(original, "suffix", "changed")
    assert declared.__kwdefaults__ is original
    with pytest.raises(behavior._AttemptBehaviorChanged):
        binding.require()


@pytest.mark.parametrize("target", ["global", "builtin_shadow"])
def test_consumed_global_and_builtin_lookup_changes_are_rejected(monkeypatch, target):
    binding = capture()

    def forbidden(*args):
        raise AssertionError("substituted builtin executed")

    if target == "global":
        monkeypatch.setattr(sys.modules[__name__], "_BEHAVIOR_GLOBAL", "changed")
    else:
        monkeypatch.setattr(sys.modules[__name__], "str", forbidden, raising=False)
    with pytest.raises(behavior._AttemptBehaviorChanged):
        binding.require()


def test_original_function_closure_cell_cannot_be_rebound():
    captured_value = "original"

    def closed():
        return captured_value

    binding = capture(functions=(closed,))
    closed.__closure__[0].cell_contents = "changed"
    with pytest.raises(behavior._AttemptBehaviorChanged):
        binding.require()


def test_supplied_function_closure_is_bound_to_its_original_function():
    callback = declared

    def closed():
        return callback

    binding = capture(functions=(declared, closed))
    closed.__closure__[0].cell_contents = lambda: None
    with pytest.raises(behavior._AttemptBehaviorChanged):
        binding.require()


@pytest.mark.parametrize("shape", ["default_list", "nested_default", "closure_list", "kw_list"])
def test_mutable_default_and_closure_profiles_are_unsupported(shape):
    if shape == "closure_list":
        captured_value = []

        def unsupported():
            return captured_value

    elif shape == "kw_list":

        def unsupported(*, value=None):
            return value

        unsupported.__kwdefaults__ = {"value": []}

    else:

        def unsupported(value=None):
            return value

        unsupported.__defaults__ = ([],) if shape == "default_list" else (([],),)
    with pytest.raises(behavior._AttemptBehaviorUnsupported):
        capture(functions=(unsupported,))


def test_added_class_data_descriptor_is_rejected_without_invocation(monkeypatch):
    binding = capture(classes=(DeclaredClass,))

    def forbidden(*args):
        raise AssertionError("added descriptor executed")

    monkeypatch.setattr(DeclaredClass, "new_field", property(forbidden), raising=False)
    with pytest.raises(behavior._AttemptBehaviorChanged):
        binding.require()


@pytest.mark.parametrize("target", ["encoder_method", "encoder_descriptor", "native_encoder"])
def test_static_json_encoder_dependencies_are_original_at_capture_and_recheck(monkeypatch, target):
    binding = capture()

    def forbidden(*args, **kwargs):
        raise AssertionError("substituted JSON encoder executed")

    if target == "encoder_method":
        monkeypatch.setattr(json.JSONEncoder, "encode", forbidden)
    elif target == "encoder_descriptor":
        monkeypatch.setattr(json.JSONEncoder, "item_separator", property(forbidden))
    else:
        monkeypatch.setattr(json.encoder, "c_make_encoder", forbidden)
    with pytest.raises(behavior._AttemptBehaviorChanged):
        binding.require()
    with pytest.raises(behavior._AttemptBehaviorChanged):
        capture()


def test_quoted_name_ordering_rebinding_is_rejected_without_a_comparison(monkeypatch):
    binding = capture()

    def forbidden(*args):
        raise AssertionError("substituted quoted key ordering executed")

    monkeypatch.setattr(quoted_name, "__lt__", forbidden)
    with pytest.raises(behavior._AttemptBehaviorChanged):
        binding.require()
    with pytest.raises(behavior._AttemptBehaviorChanged):
        capture()


def test_unknown_class_metaclass_is_rejected_without_custom_reflection():
    class UnknownMeta(type):
        def __getattribute__(cls, name):
            raise AssertionError("unknown metaclass reflected")

        def __hash__(cls):
            raise AssertionError("unknown metaclass hashed")

        def __eq__(cls, other):
            raise AssertionError("unknown metaclass compared")

    class Unknown(metaclass=UnknownMeta):
        pass

    with pytest.raises(behavior._AttemptBehaviorUnsupported):
        capture(classes=(Unknown,))


def test_retained_inventory_counts_are_stable_across_rechecks_and_shallow_copy():
    binding = capture(classes=(DeclaredClass,))
    counts = (binding.containers, binding.bindings)
    # Copying this pure inventory does not create any source-owned proof. Both
    # copies retain the same immutable baseline and charge the same graph.
    duplicate = copy(binding)
    assert duplicate.require() is None
    assert binding.require() is None
    assert (binding.containers, binding.bindings) == counts
    assert (duplicate.containers, duplicate.bindings) == counts


def test_mutated_metaclass_data_descriptor_is_not_invoked_by_rechecking():
    # Restoring __bases__ creates a foreign __mro__ tuple, so this irreversible
    # baseline-identity change belongs in a disposable interpreter, not pytest's.
    program = dedent("""
        import sys
        from enum import EnumType
        sys.path.insert(0, sys.argv[1])
        from packages.persistence import _factory_attempt_behavior as behavior
        binding = behavior._capture_attempt_behavior(functions=(), modules=())
        reached = []
        class Replacement(type):
            @property
            def __dict__(cls):
                reached.append('namespace')
                raise AssertionError('substituted metaclass descriptor executed')
            @property
            def __mro__(cls):
                reached.append('mro')
                raise AssertionError('substituted metaclass descriptor executed')
        original = EnumType.__bases__
        try:
            EnumType.__bases__ = (Replacement,)
            try:
                binding.require()
            except behavior._AttemptBehaviorChanged:
                pass
            else:
                raise AssertionError('changed metaclass was admitted')
        finally:
            EnumType.__bases__ = original
        assert reached == []
        """)
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", program, str(Path(__file__).resolve().parents[2])],
        env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("before_capture", [True, False])
def test_colliding_function_namespace_key_is_rejected_before_wrapped_lookup(before_capture):
    reached = []
    collision_hash = hash("__wrapped__")

    class CollidingKey:
        def __hash__(self):
            return collision_hash

        def __eq__(self, other):
            reached.append("equality")
            raise AssertionError("colliding function metadata key compared")

    def supplied():
        return None

    supplied.__dict__["fixture_marker"] = None
    binding = None if before_capture else capture(functions=(supplied,))
    supplied.__dict__.clear()
    supplied.__dict__[CollidingKey()] = None
    # Keep the same dictionary identity and length to reach the key-shape guard.
    assert len(supplied.__dict__) == 1
    if before_capture:
        with pytest.raises(behavior._AttemptBehaviorUnsupported):
            capture(functions=(supplied,))
    else:
        with pytest.raises(behavior._AttemptBehaviorChanged):
            binding.require()
    assert reached == []
