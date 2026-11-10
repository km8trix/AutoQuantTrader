"""Rollback faults remain visible without preventing other per-key cleanup.

Native-backed fault adapters are test instrumentation, not supported alternative
production registries. Compact receipt=None values and a constructor-free store
do not authenticate records/accounts or exercise SQL, leases or trading. Failed
registry operations remain unresolved; no complete recovery is claimed. Same-key
reentrancy and registration that raises without returning a handle remain outside
this scope.
"""

from collections.abc import MutableMapping
from weakref import finalize as real_finalize

import pytest

from packages.persistence import continuous_account as continuous
from packages.persistence.continuous_account import ResolvedContinuousIndex
from tests.unit.test_continuous_ownership_issuance import (
    MISSING,
    assert_entries_unchanged,
    compact_index,
    entries_for,
    isolated_store,
)

NO_DEFAULT = object()


class RollbackFaults:
    def __init__(self, key, faults):
        self.key = key
        self.faults = faults
        self.armed = False
        self.raised = []
        self.issued_entries = None


class NativeBackedFaultMapping(MutableMapping):
    """Delegate all storage; raise only for the armed candidate rollback key."""

    def __init__(self, backing, name, control):
        self.backing = backing
        self.name = name
        self.control = control

    def fail_selected_rollback(self, key):
        if self.control.armed and key == self.control.key:
            failure = self.control.faults.get(self.name)
            if failure is not None:
                self.control.raised.append(failure)
                raise failure

    def __getitem__(self, key):
        return self.backing[key]

    def __setitem__(self, key, value):
        self.fail_selected_rollback(key)
        self.backing[key] = value

    def __delitem__(self, key):
        self.fail_selected_rollback(key)
        del self.backing[key]

    def __iter__(self):
        return iter(self.backing)

    def __len__(self):
        return len(self.backing)

    def pop(self, key, default=NO_DEFAULT):
        self.fail_selected_rollback(key)
        if default is NO_DEFAULT:
            return self.backing.pop(key)
        return self.backing.pop(key, default)


def run_observed_rollback(monkeypatch, *, reissue, primary, faults):
    store = isolated_store()
    candidate = compact_index(store, "candidate")
    control = RollbackFaults(id(candidate), faults)
    names = ("owned", "fields", "fingerprint")
    mappings = tuple(
        NativeBackedFaultMapping(backing, name, control)
        for backing, name in zip(
            (store._owned, store._owned_fields, store._metadata_fingerprints), names, strict=True
        )
    )
    store._owned, store._owned_fields, store._metadata_fingerprints = mappings
    # Install adapters before issuing prior values, so real finalizers bind to
    # the actual current mappings rather than discarded copies of registry state.
    earlier = store._own(compact_index(store, "earlier"))
    if reissue:
        store._own(candidate)
    earlier_entries = entries_for(store, earlier)
    prior_entries = entries_for(store, candidate)
    returned_handles = []
    candidate_registrations = 0

    def finalizer_registration(value, callback, *args, **kwargs):
        nonlocal candidate_registrations
        if value is candidate:
            candidate_registrations += 1
            if candidate_registrations == 2:
                # All candidate entries were written before this primary fault.
                # Arm only rollback operations, not normal forward issuance.
                control.issued_entries = entries_for(store, candidate)
                control.armed = True
                raise primary
        handle = real_finalize(value, callback, *args, **kwargs)
        if value is candidate:
            returned_handles.append(handle)
        return handle

    try:
        with monkeypatch.context() as patch:
            patch.setattr(continuous, "finalize", finalizer_registration)
            try:
                with pytest.raises(BaseExceptionGroup) as raised:
                    store._own(candidate)
            except KeyboardInterrupt as ungrouped:
                if ungrouped is not primary and all(
                    ungrouped is not failure for failure in faults.values()
                ):
                    raise
                pytest.fail("injected interruption escaped instead of preserving the error group")

        grouped = raised.value
        assert grouped.exceptions[0] is primary
        assert control.raised
        assert {id(error) for error in control.raised} == {id(error) for error in faults.values()}
        assert len(grouped.exceptions) == 1 + len(control.raised)
        assert all(
            actual is observed
            for actual, observed in zip(grouped.exceptions[1:], control.raised, strict=True)
        )
        assert grouped.__cause__ is None and grouped.__suppress_context__ is True
        assert returned_handles and all(not handle.alive for handle in returned_handles)
        assert control.issued_entries is not None

        for name, mapping, prior, issued in zip(
            names, mappings, prior_entries, control.issued_entries, strict=True
        ):
            if name in faults:
                # The selected operation failed before changing its backing
                # entry. Retain that observed unresolved state explicitly.
                assert mapping[id(candidate)] is issued
            elif prior is MISSING:
                assert id(candidate) not in mapping
            else:
                assert mapping[id(candidate)] is prior

        # The last fingerprint registry has an observable successful cleanup
        # despite earlier registry faults: removed for new, original for reissue.
        assert "fingerprint" not in faults
        assert_entries_unchanged(store, earlier, earlier_entries)
        store._require(earlier, ResolvedContinuousIndex)
        # Do not call _require(candidate) or reinterpret a failed rollback as
        # complete recovery just because some retained values happen to match.
    finally:
        # Prior successful finalizers may later run on collection. The test fault
        # is no longer armed; it must not create unrelated unraisable exceptions.
        control.armed = False
        # Finalizer callbacks retain their adapter. Drop observation values and
        # exception tracebacks so that adapter cannot keep the candidates alive.
        control.issued_entries = None
        control.raised.clear()
        control.faults.clear()


@pytest.mark.parametrize("reissue", [False, True], ids=["new", "reissue"])
@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
def test_first_registry_rollback_fault_preserves_error_and_remaining_cleanup(
    monkeypatch, reissue, error_type
):
    primary = error_type("second finalizer registration failed")
    cleanup = RuntimeError("ownership registry rollback failed")
    run_observed_rollback(monkeypatch, reissue=reissue, primary=primary, faults={"owned": cleanup})


@pytest.mark.parametrize("reissue", [False, True], ids=["new", "reissue"])
def test_multiple_registry_rollback_faults_keep_interruption_and_last_cleanup(monkeypatch, reissue):
    primary = RuntimeError("second finalizer registration failed")
    ownership_cleanup = RuntimeError("ownership rollback failed")
    fields_cleanup = KeyboardInterrupt("fields rollback interrupted")
    run_observed_rollback(
        monkeypatch,
        reissue=reissue,
        primary=primary,
        faults={"owned": ownership_cleanup, "fields": fields_cleanup},
    )
