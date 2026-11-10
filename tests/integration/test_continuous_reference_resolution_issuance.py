"""A failed complete reference issuance retires only its actual candidate key.

The original SQLite fixture/capture/resolver authenticate actual genesis metadata.
Only reached fingerprint/finalizer or per-key rollback failures are injected. An
observer retains the actual newly built value to expose incomplete issuance; it
does not manufacture ownership. The two successful _own finalizers are not assumed
detached by outer rollback. Same-key nesting, registered-but-unreturned handles,
production occurrence, timing, PostgreSQL concurrency and wider acceptance remain
outside these cases.
"""

import gc
from dataclasses import replace
from weakref import finalize as real_finalize
from weakref import ref

import pytest

from packages.persistence import continuous_account as continuous
from packages.persistence.continuous_account import (
    ContinuousAccountConflict,
    ResolvedContinuousReference,
)
from packages.persistence.database import _repeatable_read_transaction
from tests.integration.test_continuous_publication_reference import capture
from tests.integration.test_continuous_publication_reference import h as h
from tests.unit.test_continuous_ownership_rollback_errors import (
    NativeBackedFaultMapping,
    RollbackFaults,
)


def resolution_registries(store):
    return (
        store._owned,
        store._owned_fields,
        store._metadata_fingerprints,
        store._reference_fingerprints,
    )


def resolution_entries(store):
    return tuple(dict(registry.items()) for registry in resolution_registries(store))


def assert_original_resolution_entries(store, before):
    for registry, original in zip(resolution_registries(store), before, strict=True):
        for key, value in original.items():
            assert registry[key] is value


def raw_entries(store):
    return (dict(store._reference_captures.items()), dict(store._reference_capture_fields))


def assert_raw_entries_unchanged(store, before):
    for registry, original in zip(
        (store._reference_captures, store._reference_capture_fields), before, strict=True
    ):
        assert set(registry) == set(original)
        for key, value in original.items():
            assert registry[key] is value


def assert_failed_resolution_denied(h, candidate):
    for require in (
        lambda: h.store._require(candidate, ResolvedContinuousReference),
        lambda: h.store.require_reference(candidate),
    ):
        with pytest.raises(ContinuousAccountConflict, match=r"^OWNED_CONTINUOUS_VALUE_REQUIRED$"):
            require()
    with (
        _repeatable_read_transaction(h.engine) as connection,
        pytest.raises(ContinuousAccountConflict, match=r"^OWNED_CONTINUOUS_VALUE_REQUIRED$"),
    ):
        h.store.recheck_reference_in_transaction(connection, candidate)


@pytest.mark.parametrize("stage", ["fingerprint", "finalizer"])
@pytest.mark.parametrize(
    "error_type", [RuntimeError, KeyboardInterrupt, ValueError, TypeError, KeyError, UnicodeError]
)
def test_failed_resolution_restores_all_candidate_entries_and_original_error(
    h, monkeypatch, stage, error_type
):
    raw = capture(h)
    earlier = h.store.resolve_reference(raw)
    h.store.require_reference(earlier)
    before = resolution_entries(h.store)
    raw_before = raw_entries(h.store)
    failure = error_type("selected complete-reference issuance failure")
    original_fingerprint = continuous._reference_fingerprint
    candidates, own_handles = [], []

    def fingerprint(snapshot, journal, prior):
        if stage == "fingerprint" and snapshot is raw:
            assert len(candidates) == 1 and len(own_handles) == 2
            raise failure
        return original_fingerprint(snapshot, journal, prior)

    def register_finalizer(value, callback, *args, **kwargs):
        if type(value) is ResolvedContinuousReference and value.snapshot is raw:
            if not candidates:
                candidates.append(value)
            assert candidates[0] is value
            if callback.__self__ is h.store._reference_fingerprints:
                assert len(own_handles) == 2
                if stage == "finalizer":
                    raise failure
            handle = real_finalize(value, callback, *args, **kwargs)
            if (
                callback.__self__ is h.store._owned_fields
                or callback.__self__ is h.store._metadata_fingerprints
            ):
                own_handles.append(handle)
            return handle
        return real_finalize(value, callback, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(continuous, "_reference_fingerprint", fingerprint)
        patch.setattr(continuous, "finalize", register_finalizer)
        try:
            h.store.resolve_reference(raw)
        except BaseException as actual:
            if isinstance(actual, KeyboardInterrupt) and actual is not failure:
                raise
            if error_type in (ValueError, TypeError, KeyError, UnicodeError):
                assert type(actual) is ContinuousAccountConflict
                assert str(actual) == "CONTINUOUS_RETAINED_REFERENCE_INVALID"
                assert actual.__cause__ is None and actual.__suppress_context__ is True
                assert actual.__context__ is failure
            else:
                assert actual is failure
        else:
            pytest.fail("the selected resolution issuance boundary did not raise")

    assert len(candidates) == 1 and len(own_handles) == 2
    candidate = candidates[0]
    assert candidate is not earlier and candidate.snapshot is raw
    for registry, original in zip(resolution_registries(h.store), before, strict=True):
        assert set(registry) == set(original)
        assert id(candidate) not in registry
    assert_original_resolution_entries(h.store, before)
    assert_raw_entries_unchanged(h.store, raw_before)
    assert_failed_resolution_denied(h, candidate)
    h.store._require_reference_capture(raw)
    h.store.require_reference(earlier)
    # The old two _own callbacks may remain live until actual collection. Their
    # detachment is not a condition of the outer four-registry rollback.
    recovered = h.store.resolve_reference(raw)
    assert recovered is not candidate and recovered.receipt == earlier.receipt
    h.store.require_reference(recovered)
    assert_original_resolution_entries(h.store, before)
    h.store.require_reference(earlier)


def test_original_complete_reference_rejects_equal_copy_and_foreign_owner(h):
    raw = capture(h)
    value = h.store.resolve_reference(raw)
    h.store.require_reference(value)
    assert value.snapshot is raw and value.receipt.commit.sequence == 1
    with _repeatable_read_transaction(h.engine) as connection:
        h.store.recheck_reference_in_transaction(connection, value)
    copied = replace(value)
    assert copied is not value and copied == value
    with pytest.raises(ContinuousAccountConflict, match=r"^OWNED_CONTINUOUS_VALUE_REQUIRED$"):
        h.store.require_reference(copied)
    with pytest.raises(ContinuousAccountConflict, match=r"^OWNED_CONTINUOUS_VALUE_REQUIRED$"):
        h.new_store().require_reference(value)
    h.store.require_reference(value)


def test_original_complete_reference_collection_cleans_all_four_registries(h):
    raw = capture(h)
    earlier = h.store.resolve_reference(raw)
    before = resolution_entries(h.store)
    candidate = h.store.resolve_reference(raw)
    h.store.require_reference(candidate)
    key, weak = id(candidate), ref(candidate)
    assert all(key in registry for registry in resolution_registries(h.store))
    del candidate
    gc.collect()
    assert weak() is None
    for registry, original in zip(resolution_registries(h.store), before, strict=True):
        assert key not in registry and set(registry) == set(original)
    assert_original_resolution_entries(h.store, before)
    h.store._require_reference_capture(raw)
    h.store.require_reference(earlier)


@pytest.mark.parametrize("error_type", [RuntimeError, ValueError])
@pytest.mark.parametrize("fault_set", ["weak", "weak-and-reference"])
def test_failed_resolution_registry_rollback_groups_faults_and_keeps_unresolved_entries(
    h, monkeypatch, error_type, fault_set
):
    primary = error_type("final reference callback registration failed before registration")
    weak_cleanup = RuntimeError("resolved weak-entry rollback failed")
    reference_cleanup = KeyboardInterrupt("resolved reference-fingerprint rollback interrupted")
    faults = {"owned": weak_cleanup}
    if fault_set == "weak-and-reference":
        faults["reference"] = reference_cleanup
    control = RollbackFaults(None, faults)
    names = ("owned", "fields", "fingerprint", "reference")
    mappings = tuple(
        NativeBackedFaultMapping(registry, name, control)
        for registry, name in zip(resolution_registries(h.store), names, strict=True)
    )
    (
        h.store._owned,
        h.store._owned_fields,
        h.store._metadata_fingerprints,
        h.store._reference_fingerprints,
    ) = mappings
    # Actual earlier finalizers bind to the current native-backed adapters.
    raw = capture(h)
    earlier = h.store.resolve_reference(raw)
    before = resolution_entries(h.store)
    raw_before = raw_entries(h.store)
    expected_cleanup = tuple(faults[name] for name in names if name in faults)
    candidates, own_handles = [], []

    def register_finalizer(value, callback, *args, **kwargs):
        if type(value) is ResolvedContinuousReference and value.snapshot is raw:
            if not candidates:
                candidates.append(value)
            assert candidates[0] is value
            if callback.__self__ is h.store._reference_fingerprints:
                assert len(own_handles) == 2
                control.key = id(value)
                control.issued_entries = tuple(registry[control.key] for registry in mappings)
                control.armed = True
                raise primary
            handle = real_finalize(value, callback, *args, **kwargs)
            own_handles.append(handle)
            return handle
        return real_finalize(value, callback, *args, **kwargs)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(continuous, "finalize", register_finalizer)
            try:
                with pytest.raises(BaseExceptionGroup) as raised:
                    h.store.resolve_reference(raw)
            except KeyboardInterrupt as interrupted:
                if all(interrupted is not error for error in expected_cleanup):
                    raise
                pytest.fail("injected rollback interruption escaped without its primary group")

        group = raised.value
        assert len(candidates) == 1 and len(own_handles) == 2
        assert len(group.exceptions) == 1 + len(expected_cleanup)
        assert group.exceptions[0] is primary
        assert len(control.raised) == len(expected_cleanup)
        for actual, observed, expected in zip(
            group.exceptions[1:], control.raised, expected_cleanup, strict=True
        ):
            assert actual is observed and observed is expected
        assert group.__cause__ is None and group.__suppress_context__ is True
        candidate = candidates[0]
        key = id(candidate)
        for name, mapping, original, issued in zip(
            names, mappings, before, control.issued_entries, strict=True
        ):
            if name in faults:
                assert mapping[key] is issued
                assert set(mapping) == set(original) | {key}
            else:
                assert key not in mapping and set(mapping) == set(original)
        # Later field/metadata restorations were attempted after the weak pop
        # failed. Failed mappings retain their explicitly unresolved entries;
        # do not call this candidate's guards or assert successful recovery.
        assert_original_resolution_entries(h.store, before)
        assert_raw_entries_unchanged(h.store, raw_before)
        h.store._require_reference_capture(raw)
        h.store.require_reference(earlier)
    finally:
        # Real _own callbacks retain their adapters. Break observation/error
        # references and disarm faults before actual finalizer collection.
        control.armed = False
        control.issued_entries = None
        control.raised.clear()
        control.faults.clear()
        candidates.clear()


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
def test_failed_resolution_preserves_successful_unrelated_key_reentrancy(
    h, monkeypatch, error_type
):
    selected_raw = capture(h)
    other_raw = capture(h)
    assert selected_raw is not other_raw
    earlier = h.store.resolve_reference(selected_raw)
    before = resolution_entries(h.store)
    raw_before = raw_entries(h.store)
    failure = error_type("selected fingerprint failed after unrelated reference resolution")
    original_fingerprint = continuous._reference_fingerprint
    candidates, own_handles, nested = [], [], []
    triggered = False

    def register_finalizer(value, callback, *args, **kwargs):
        handle = real_finalize(value, callback, *args, **kwargs)
        if type(value) is ResolvedContinuousReference and value.snapshot is selected_raw:
            if not candidates:
                candidates.append(value)
            assert candidates[0] is value
            own_handles.append(handle)
        return handle

    def fingerprint(snapshot, journal, prior):
        nonlocal triggered
        if snapshot is selected_raw and not triggered:
            triggered = True
            assert len(candidates) == 1 and len(own_handles) == 2
            value = h.store.resolve_reference(other_raw)
            nested.append(
                (value, tuple(registry[id(value)] for registry in resolution_registries(h.store)))
            )
            raise failure
        return original_fingerprint(snapshot, journal, prior)

    with monkeypatch.context() as patch:
        patch.setattr(continuous, "finalize", register_finalizer)
        patch.setattr(continuous, "_reference_fingerprint", fingerprint)
        try:
            h.store.resolve_reference(selected_raw)
        except BaseException as actual:
            if actual is not failure:
                raise
        else:
            pytest.fail("the selected reentrant issuance boundary did not raise")

    assert triggered and len(candidates) == 1 and len(nested) == 1
    candidate = candidates[0]
    value, issued = nested[0]
    assert value.snapshot is other_raw and value is not candidate
    for registry, original, nested_entry in zip(
        resolution_registries(h.store), before, issued, strict=True
    ):
        assert id(candidate) not in registry
        assert set(registry) == set(original) | {id(value)}
        assert registry[id(value)] is nested_entry
    assert_original_resolution_entries(h.store, before)
    assert_raw_entries_unchanged(h.store, raw_before)
    assert_failed_resolution_denied(h, candidate)
    h.store.require_reference(earlier)
    h.store.require_reference(value)
    h.store._require_reference_capture(selected_raw)
    h.store._require_reference_capture(other_raw)
