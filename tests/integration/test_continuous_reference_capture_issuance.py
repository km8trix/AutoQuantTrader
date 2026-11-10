"""Reached raw-reference issuance failures retire only the attempted identity.

The existing SQLite harness publishes actual genesis. Capture, physical read
transactions and reference validation remain original. An injector retains the
actual failed raw solely to observe partial issuance, not to manufacture ownership.
Finalizer faults occur before registration; a registered but unreturned handle is
not covered. These cases establish conditional lifecycle behavior, not a production
occurrence, timing benefit, PostgreSQL concurrency or wider study acceptance.
"""

import gc
from dataclasses import fields as real_fields
from dataclasses import replace
from weakref import finalize as real_finalize
from weakref import ref

import pytest

from packages.persistence import continuous_account as continuous
from packages.persistence.continuous_account import (
    ContinuousAccountConflict,
    ContinuousReferenceSnapshot,
)
from tests.integration.test_continuous_publication_reference import capture
from tests.integration.test_continuous_publication_reference import h as h
from tests.unit.test_continuous_ownership_rollback_errors import (
    NativeBackedFaultMapping,
    RollbackFaults,
)


def capture_entries(store):
    return (
        dict(store._reference_captures.items()),
        dict(store._reference_capture_fields),
    )


def assert_capture_entries_unchanged(store, originals):
    for registry, original in zip(
        (store._reference_captures, store._reference_capture_fields), originals, strict=True
    ):
        assert set(registry) == set(original)
        for identity, value in original.items():
            assert registry[identity] is value


@pytest.mark.parametrize("stage", ["fields", "finalizer"])
@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
def test_failed_raw_capture_restores_entries_and_preserves_original_reference(
    h, monkeypatch, stage, error_type
):
    earlier = capture(h)
    earlier_value = h.store.resolve_reference(earlier)
    h.store.require_reference(earlier_value)
    before = capture_entries(h.store)
    failure = error_type("selected raw-reference issuance failure")
    reached = []

    def discover_fields(value):
        if stage == "fields" and type(value) is ContinuousReferenceSnapshot:
            reached.append(value)
            raise failure
        return real_fields(value)

    def register_finalizer(value, callback, *args, **kwargs):
        if stage == "finalizer" and type(value) is ContinuousReferenceSnapshot:
            reached.append(value)
            raise failure
        return real_finalize(value, callback, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(continuous, "fields", discover_fields)
        patch.setattr(continuous, "finalize", register_finalizer)
        try:
            capture(h)
        except BaseException as actual:
            # An actual external interrupt or other unexpected error must escape.
            if actual is not failure:
                raise
        else:
            pytest.fail("the selected issuance boundary did not raise")

    assert len(reached) == 1
    failed_raw = reached[0]
    assert type(failed_raw) is ContinuousReferenceSnapshot
    assert failed_raw is not earlier
    assert failed_raw.current == earlier.current and failed_raw.lease == earlier.lease
    assert_capture_entries_unchanged(h.store, before)
    assert id(failed_raw) not in h.store._reference_captures
    assert id(failed_raw) not in h.store._reference_capture_fields
    with pytest.raises(
        ContinuousAccountConflict, match=r"^OWNED_CONTINUOUS_REFERENCE_CAPTURE_REQUIRED$"
    ):
        h.store._require_reference_capture(failed_raw)
    h.store._require_reference_capture(earlier)
    h.store.require_reference(earlier_value)

    # Fault restoration permits a new original capture of unchanged retained rows.
    recaptured = capture(h)
    assert recaptured is not failed_raw
    assert recaptured.current == earlier.current and recaptured.lease == earlier.lease
    h.store._require_reference_capture(recaptured)
    recovered_value = h.store.resolve_reference(recaptured)
    h.store.require_reference(recovered_value)
    assert recovered_value.receipt == earlier_value.receipt
    for identity, value in before[0].items():
        assert h.store._reference_captures[identity] is value
    for identity, value in before[1].items():
        assert h.store._reference_capture_fields[identity] is value
    h.store.require_reference(earlier_value)


def test_original_raw_capture_resolves_and_equal_copy_is_not_owned(h):
    raw = capture(h)
    assert type(raw) is ContinuousReferenceSnapshot
    h.store._require_reference_capture(raw)
    value = h.store.resolve_reference(raw)
    h.store.require_reference(value)
    assert value.snapshot is raw
    assert value.receipt.commit.sequence == 1
    assert value.previous_receipt is None and value.source_lease is None
    copied = replace(raw)
    assert copied is not raw and copied == raw
    with pytest.raises(
        ContinuousAccountConflict, match=r"^OWNED_CONTINUOUS_REFERENCE_CAPTURE_REQUIRED$"
    ):
        h.store.resolve_reference(copied)
    h.store.require_reference(value)


def test_original_raw_capture_weak_cleanup_preserves_earlier_reference(h):
    earlier = capture(h)
    earlier_value = h.store.resolve_reference(earlier)
    before = capture_entries(h.store)
    candidate = capture(h)
    key, weak = id(candidate), ref(candidate)
    h.store._require_reference_capture(candidate)
    assert key in h.store._reference_captures
    assert key in h.store._reference_capture_fields
    del candidate
    gc.collect()
    assert weak() is None
    assert key not in h.store._reference_captures
    assert key not in h.store._reference_capture_fields
    assert_capture_entries_unchanged(h.store, before)
    h.store._require_reference_capture(earlier)
    h.store.require_reference(earlier_value)


def observe_failed_raw_registry_rollback(h, monkeypatch, faults):
    control = RollbackFaults(None, faults)
    owned = NativeBackedFaultMapping(h.store._reference_captures, "owned", control)
    fields = NativeBackedFaultMapping(h.store._reference_capture_fields, "fields", control)
    h.store._reference_captures, h.store._reference_capture_fields = owned, fields
    # Install native-backed adapters before earlier issuance so its real cleanup
    # callback uses the actual current field mapping. No backing storage is copied.
    earlier = capture(h)
    earlier_value = h.store.resolve_reference(earlier)
    before = capture_entries(h.store)
    primary = RuntimeError("raw finalizer registration failed before returning a handle")
    expected_cleanup = tuple(faults[name] for name in ("owned", "fields") if name in faults)
    reached = []

    def register_finalizer(value, callback, *args, **kwargs):
        if type(value) is ContinuousReferenceSnapshot:
            reached.append(value)
            control.key = id(value)
            control.issued_entries = (owned[control.key], fields[control.key])
            assert control.issued_entries[0] is value
            # Both original writes completed. Fault only candidate rollback pops,
            # never forward registration or operations on an earlier raw value.
            control.armed = True
            raise primary
        return real_finalize(value, callback, *args, **kwargs)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(continuous, "finalize", register_finalizer)
            try:
                with pytest.raises(BaseExceptionGroup) as raised:
                    capture(h)
            except KeyboardInterrupt as interrupted:
                if all(interrupted is not error for error in expected_cleanup):
                    raise
                pytest.fail("injected rollback interruption escaped without its primary group")

        group = raised.value
        assert len(reached) == 1
        assert len(group.exceptions) == 1 + len(expected_cleanup)
        assert group.exceptions[0] is primary
        assert len(control.raised) == len(expected_cleanup)
        for actual, observed, expected in zip(
            group.exceptions[1:], control.raised, expected_cleanup, strict=True
        ):
            assert actual is observed and observed is expected
        assert group.__cause__ is None and group.__suppress_context__ is True
        failed_raw = reached[0]
        key = id(failed_raw)
        # A failed pop leaves exactly the issued native backing entry unresolved.
        # Do not call the failed raw's guard or claim complete recovery.
        assert owned[key] is failed_raw
        assert set(owned) == set(before[0]) | {key}
        if "fields" in faults:
            assert fields[key] is control.issued_entries[1]
            assert set(fields) == set(before[1]) | {key}
        else:
            assert key not in fields
            assert set(fields) == set(before[1])
        for registry, original in zip((owned, fields), before, strict=True):
            for identity, value in original.items():
                assert registry[identity] is value
        h.store._require_reference_capture(earlier)
        h.store.require_reference(earlier_value)
    finally:
        # Existing stdlib callbacks retain their adapter. Disarm and clear held
        # observations/errors so they cannot retain the attempted raw or re-raise
        # the test fault during later real finalizer collection.
        control.armed = False
        control.issued_entries = None
        control.raised.clear()
        control.faults.clear()
        reached.clear()


def test_raw_weak_registry_pop_failure_keeps_primary_and_finishes_fields_cleanup(h, monkeypatch):
    cleanup = RuntimeError("raw weak registry rollback failed")
    observe_failed_raw_registry_rollback(h, monkeypatch, {"owned": cleanup})


def test_both_raw_registry_pop_failures_preserve_error_order_and_unresolved_entries(h, monkeypatch):
    ownership_cleanup = RuntimeError("raw weak registry rollback failed")
    fields_cleanup = KeyboardInterrupt("raw fields rollback interrupted")
    observe_failed_raw_registry_rollback(
        h, monkeypatch, {"owned": ownership_cleanup, "fields": fields_cleanup}
    )
