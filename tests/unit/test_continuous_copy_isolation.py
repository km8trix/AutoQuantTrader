"""Copy-test isolation preserves the strict original factory behavior inventory."""

import sys
from copy import copy

import pytest

from packages.persistence import continuous_integrity as integrity
from packages.persistence import continuous_runtime_attempt_sources as attempt_sources
from packages.persistence._factory_attempt_behavior import _AttemptBehaviorChanged
from tests.fixtures.copy_isolation import copy_preserving_class_inventory


@pytest.mark.skipif(
    sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 12, 13),
    reason="original behavior inventory is qualified only for CPython 3.12.13",
)
@pytest.mark.parametrize(
    "kind", [integrity.SqlContinuousIntegrityReader, integrity.SqlContinuousCommitComposer]
)
def test_copy_cache_changes_remain_rejected_but_isolated_copy_restores_original_guard(kind):
    # Uninitialized exact owners test only copy's class-metadata effect; they
    # acquire no engine, registration, episode, lease or proof authority.
    root = attempt_sources._FACTORY_FINGERPRINT_RUNTIME["root"]
    assert root is not None
    root.require()
    original_namespace = tuple(vars(kind).items())
    original = object.__new__(kind)
    original.marker = object()
    missing = object()
    before = vars(kind).get("__slotnames__", missing)
    assert before is missing
    try:
        copied = copy(original)
        assert copied is not original and copied.marker is original.marker
        assert type(vars(kind)["__slotnames__"]) is list
        assert vars(kind)["__slotnames__"] == []
        with pytest.raises(_AttemptBehaviorChanged, match="CLASS_NAMESPACE_CHANGED"):
            root.require()
    finally:
        if before is missing:
            delattr(kind, "__slotnames__")
        else:
            kind.__slotnames__ = before
    root.require()

    copied = copy_preserving_class_inventory(original)
    assert copied is not original and copied.marker is original.marker
    restored_namespace = tuple(vars(kind).items())
    assert len(restored_namespace) == len(original_namespace)
    assert all(
        actual_name == name and actual is value
        for (actual_name, actual), (name, value) in zip(
            restored_namespace, original_namespace, strict=True
        )
    )
    root.require()


def test_copy_preserves_existing_slot_cache_identity():
    class Record:
        pass

    cache = []
    Record.__slotnames__ = cache
    original = Record()
    original.marker = object()
    copied = copy_preserving_class_inventory(original)
    assert copied is not original and copied.marker is original.marker
    assert vars(Record)["__slotnames__"] is cache


@pytest.mark.parametrize("cached", [False, True])
def test_failed_copy_restores_cache_and_preserves_original_exception(cached):
    failure = RuntimeError("copy sentinel")

    class Record:
        def __copy__(self):
            type(self).__slotnames__ = ["temporary"]
            raise failure

    cache = []
    if cached:
        Record.__slotnames__ = cache
    with pytest.raises(RuntimeError) as caught:
        copy_preserving_class_inventory(Record())
    assert caught.value is failure
    if cached:
        assert vars(Record)["__slotnames__"] is cache
    else:
        assert "__slotnames__" not in vars(Record)
