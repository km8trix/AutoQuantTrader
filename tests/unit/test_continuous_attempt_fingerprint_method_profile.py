"""Pure namespace-profile negatives, never authenticated factory contexts."""

import pytest

from packages.persistence import continuous_integrity as integrity


def reader_namespace():
    # Exact uninitialized objects test only this private metadata predicate.
    # They have no engine, owner registration, episode, lease or authority.
    reader = object.__new__(integrity.SqlContinuousIntegrityReader)
    reader.composer = object.__new__(integrity.SqlContinuousCommitComposer)
    return reader


@pytest.mark.parametrize("target", ["reader", "composer"])
def test_instance_method_shadow_is_rejected_without_invoking_the_shadow(target):
    reader = reader_namespace()

    def forbidden(*args):
        raise AssertionError("shadow method invoked")

    if target == "reader":
        reader._require_daily_episode_identity = forbidden
    else:
        reader.composer._require_integrity_daily = forbidden
    assert integrity._factory_fingerprint_method_profile(reader) is False


@pytest.mark.parametrize("target", ["reader", "composer"])
def test_foreign_namespace_key_is_rejected_before_colliding_method_lookup(target):
    reader = reader_namespace()
    reached = []
    name = "_require_daily_episode_identity" if target == "reader" else "_require_integrity_daily"

    class ForeignKey:
        def __hash__(self):
            return hash(name)

        def __eq__(self, other):
            reached.append("equality")
            raise AssertionError("foreign metadata key compared")

    namespace = vars(reader if target == "reader" else reader.composer)
    namespace[ForeignKey()] = None
    assert integrity._factory_fingerprint_method_profile(reader) is False
    assert reached == []


@pytest.mark.parametrize("target", ["reader", "composer"])
def test_namespace_subclass_is_rejected_without_custom_iteration(target):
    reader = reader_namespace()

    class ForeignDictionary(dict):
        def __iter__(self):
            raise AssertionError("foreign namespace iterated")

        def __contains__(self, key):
            raise AssertionError("foreign namespace queried")

    owner = reader if target == "reader" else reader.composer
    owner.__dict__ = ForeignDictionary(vars(owner))
    assert integrity._factory_fingerprint_method_profile(reader) is False


@pytest.mark.parametrize("target", ["reader", "composer"])
def test_combined_namespace_allowance_is_shared_and_fixed(target):
    reader = reader_namespace()
    namespace = vars(reader if target == "reader" else reader.composer)
    for index in range(127):
        namespace[f"fixture_{index}"] = None
    # This only qualifies a dictionary shape, never source/reader ownership.
    assert len(vars(reader)) + len(vars(reader.composer)) == 128
    assert integrity._factory_fingerprint_method_profile(reader) is True
    namespace["over_limit"] = None
    assert integrity._factory_fingerprint_method_profile(reader) is False
