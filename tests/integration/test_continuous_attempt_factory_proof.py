"""Actual source ownership and signed-genesis negative controls for factory proofs.

The pending fixture does not establish signed factory history. These tests never
manufacture an active context or claim that its nonempty optimized path ran.
"""

import gc
import sys
from copy import copy
from itertools import islice
from types import MappingProxyType

import pytest

from packages.persistence import _factory_attempt_fingerprint as proof_data
from packages.persistence import continuous_integrity as integrity
from packages.persistence import continuous_runtime_attempt_sources as attempt_sources
from packages.persistence.continuous_runtime_attempt_sources import (
    ContinuousRuntimeAttemptSourceError,
)
from packages.persistence.daily_runtime_risk import RuntimeReadBudget
from tests.integration.test_continuous_factory_integrity_result import (
    assert_closed,
)
from tests.integration.test_continuous_factory_integrity_result import (
    configured as configured,
)
from tests.integration.test_continuous_factory_integrity_result import (
    original_factory as original_factory,
)
from tests.integration.test_continuous_runtime_attempt_sources import (
    attempt_case as attempt_case,
)
from tests.integration.test_continuous_runtime_attempt_sources import pending

_QUALIFIED_NATIVE_PROFILE = sys.implementation.name == "cpython" and sys.version_info[:3] == (
    3,
    12,
    13,
)


def _resolved_pending(attempt_case):
    case, _producer, owner, _previous, _current, admission = attempt_case
    prepared = pending(attempt_case)
    plan = owner.prepare_attempt_source_read((prepared.reference,))
    with case.store.write_transaction() as connection:
        snapshot = owner.capture_attempt_sources_in_transaction(
            connection,
            plan,
            account_id=case.scope.account_id,
            budget=RuntimeReadBudget(),
        )
    resolved = owner.resolve_attempt_sources(snapshot, admissions=(admission,))
    owner.require_resolved(resolved)
    return owner, resolved


def _copy_preserving_class_inventory(value):
    """Keep stdlib's lazy class slot cache out of original-object copy tests."""
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


def _mutate_provenance_scalar(resolved):
    """Change one detached fixture row, never its persisted database source."""
    for table in resolved.state.captured.provenance[:8]:
        if table.table.name != "daily_runtime_assignments" or not table.rows:
            continue
        row = table.rows[0]
        assert type(row) is MappingProxyType
        referents = gc.get_referents(row)
        assert len(referents) == 1 and type(referents[0]) is dict
        backing = referents[0]
        for key, original in islice(dict.items(backing), 32):
            if type(original) is str:
                dict.__setitem__(backing, key, original + "-changed-fixture-row")
                return backing, key, original
    pytest.fail("fixture lacks a bounded exact daily assignment provenance row")


def test_deep_provenance_change_reaches_the_original_final_fingerprint_guard(attempt_case):
    owner, resolved = _resolved_pending(attempt_case)
    if _QUALIFIED_NATIVE_PROFILE:
        _require_actual_pending_data_profile(owner, resolved)
    else:
        # The ordinary original validation/mutation assertions below still run
        # on supported Python versions outside the optional native proof profile.
        assert not proof_data._supported_runtime()
    original = owner._fingerprint(resolved)
    backing, key, before = _mutate_provenance_scalar(resolved)
    try:
        owner._require(resolved, type(resolved))
        assert owner._fingerprint(resolved) != original
        # This exact error proves original reference/descriptor/outcome guards
        # succeeded first; the final full content comparison alone detected it.
        with pytest.raises(
            ContinuousRuntimeAttemptSourceError, match="ATTEMPT_ORIGINAL_RESOLVED_CONTENT_CHANGED"
        ):
            owner.require_resolved(resolved)
    finally:
        dict.__setitem__(backing, key, before)
    owner.require_resolved(resolved)


def _require_actual_pending_data_profile(owner, resolved):
    source_behavior, root_behavior, _module = attempt_sources._factory_fingerprint_behaviors()
    token = proof_data._GET_ABC_TOKEN()
    owner.require_resolved(resolved)
    reserved_containers = (
        attempt_sources._FACTORY_ROOT_CONTAINERS
        + attempt_sources._FACTORY_SOURCE_CONTAINERS
        + source_behavior.containers
        + root_behavior.containers
    )
    reserved_bindings = (
        attempt_sources._FACTORY_ROOT_BINDINGS
        + attempt_sources._FACTORY_SOURCE_BINDINGS
        + source_behavior.bindings
        + root_behavior.bindings
    )
    # This uses an actual owned source and unchanged full validation to check
    # the production projection and remaining shared budget. It grants no
    # factory authority and creates no original factory context or proof token.
    data = proof_data._try_seal_attempt_data(
        (resolved,),
        selectors=attempt_sources._FACTORY_DATA_SELECTORS,
        selector_roles=attempt_sources._FACTORY_DATA_ROLES,
        allowed_records=attempt_sources._FACTORY_DATA_RECORDS,
        selector_objects=attempt_sources._FACTORY_DATA_TABLES,
        mapping_token=token,
        max_containers=integrity._MAX_FACTORY_CONTAINERS - reserved_containers,
        max_bindings=integrity._MAX_FACTORY_BINDINGS - reserved_bindings,
    )
    assert data is not None, "actual owned pending source has no admitted projection"
    assert data.require() is None


def test_actual_owned_pending_source_cannot_issue_factory_proof_from_an_opaque_claim(attempt_case):
    owner, resolved = _resolved_pending(attempt_case)
    # Actual source tokens are necessary but cannot qualify an unregistered
    # factory operation, episode, or caller-supplied context by themselves.
    original_contexts = tuple(integrity._FACTORY_FINGERPRINTS.items())
    unregistered_context = integrity._FactoryFingerprintContext()
    contexts = (
        object(),
        unregistered_context,
        _copy_preserving_class_inventory(unregistered_context),
    )
    candidates = (
        (owner, resolved),
        (_copy_preserving_class_inventory(owner), resolved),
        (owner, _copy_preserving_class_inventory(resolved)),
    )
    for source, value in candidates:
        for context in contexts:
            try:
                issued = source._issue_factory_fingerprint(
                    value,
                    context=context,
                    max_containers=16_384,
                    max_bindings=131_072,
                )
            except ValueError:
                pass
            else:
                assert not _QUALIFIED_NATIVE_PROFILE and issued is None
            for use in (object(), integrity._FactoryFingerprintUse()):
                with pytest.raises(ValueError):
                    source._require_resolved_for_factory(value, proof=object(), use=use)
            with pytest.raises(ValueError):
                source._retire_factory_fingerprint(object(), context=context)
    assert tuple(integrity._FACTORY_FINGERPRINTS.items()) == original_contexts
    owner.require_resolved(resolved)


def test_standalone_original_owner_validation_still_fingerprints_every_call(attempt_case):
    owner, resolved = _resolved_pending(attempt_case)
    fingerprint_code = type(owner)._fingerprint.__code__
    require_code = type(owner)._require.__code__
    reference_code = type(owner.accounts).require_reference.__code__
    events = []

    def trace(frame, event, argument):
        if event == "call":
            if frame.f_code is fingerprint_code and frame.f_locals.get("value") is resolved:
                events.append("fingerprint")
            elif frame.f_code is require_code and frame.f_locals.get("value") is resolved:
                events.append("original-owner")
            elif frame.f_code is reference_code and frame.f_locals.get("self") is owner.accounts:
                events.append("account-reference")

    previous = sys.getprofile()
    try:
        sys.setprofile(trace)
        owner.require_resolved(resolved)
        owner.require_resolved(resolved)
        with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
            owner.require_resolved(_copy_preserving_class_inventory(resolved))
    finally:
        sys.setprofile(previous)
    assert events == ["original-owner", "account-reference", "fingerprint"] * 2


def test_actual_signed_genesis_without_attempt_sources_never_issues_a_proof(original_factory):
    _fixture, factory = original_factory
    reader = factory.integrity
    owner = factory.runtime_sources._attempt_reader()
    issue_code = type(owner)._issue_factory_fingerprint.__code__
    events = []

    def trace(frame, event, argument):
        if event == "call" and frame.f_code is issue_code:
            events.append("issue")

    previous = sys.getprofile()
    try:
        sys.setprofile(trace)
        with reader.original_factory_read() as actual:
            assert actual.receipt.commit.sequence == 1
            reader.require_original_factory_values()
            current = reader.read_original_daily_for_factory()
            assert current.attempt_sources is None
            reader.require_original_factory_values()
    finally:
        sys.setprofile(previous)
    assert events == []
    assert_closed(reader)
