"""Conditional ownership issuance preserves prior entries on a reached failure.

These units use real weak dictionaries, compact metadata fingerprints, public
owned-value classes and stdlib finalizers. Receipt=None and a synthetic row are
deliberately not record/account authentication. The store constructor is bypassed;
no SQL, artifacts, leases, composer, codec or trading authority is exercised.
Same-key reentrant issuance and a finalizer that registers then raises without
returning its handle are not qualified by these cases.
"""

import gc
from dataclasses import fields as real_fields
from weakref import WeakValueDictionary, ref
from weakref import finalize as real_finalize

import pytest

from packages.persistence import continuous_account as continuous
from packages.persistence.continuous_account import (
    ContinuousAccountConflict,
    ContinuousIndexSnapshot,
    ResolvedContinuousIndex,
    SqlContinuousAccount,
)

MISSING = object()


def isolated_store():
    store = SqlContinuousAccount.__new__(SqlContinuousAccount)
    store._seal = object()
    store._owned = WeakValueDictionary()
    store._owned_fields = {}
    store._metadata_fingerprints = {}
    return store


def compact_index(store, label):
    return ResolvedContinuousIndex(
        ContinuousIndexSnapshot(None, {"label": label, "sequence": 1}),
        None,
        None,
        store._seal,
    )


def entries_for(store, value):
    key = id(value)
    return tuple(
        mapping.get(key, MISSING)
        for mapping in (store._owned, store._owned_fields, store._metadata_fingerprints)
    )


def assert_entries_unchanged(store, value, expected):
    for mapping, original in zip(
        (store._owned, store._owned_fields, store._metadata_fingerprints), expected, strict=True
    ):
        if original is MISSING:
            assert id(value) not in mapping
        else:
            assert mapping[id(value)] is original


class FailingDetachHandle:
    """Exercise cleanup-error reporting while retiring an actual stdlib handle."""

    def __init__(self, handle, failure):
        self.handle = handle
        self.failure = failure

    @property
    def alive(self):
        return self.handle.alive

    def detach(self):
        self.handle.detach()
        raise self.failure

    def __call__(self):
        return self.handle()


def inject_issuance_failure(
    patch, store, candidate, stage, failure, *, reenter=None, detach_failure=None
):
    """Delegate actual operations, except the selected reached failure call."""
    original_fingerprint = store._metadata_fingerprint
    observed_handles = []
    candidate_finalizes = 0

    def discover_fields(value):
        if value is candidate and stage == "fields":
            raise failure
        return real_fields(value)

    def fingerprint(value):
        if value is candidate and stage == "fingerprint":
            if reenter is not None:
                reenter()
            raise failure
        return original_fingerprint(value)

    def register_finalizer(value, callback, *args, **kwargs):
        nonlocal candidate_finalizes
        if value is candidate:
            candidate_finalizes += 1
            if (stage == "first_finalize" and candidate_finalizes == 1) or (
                stage == "second_finalize" and candidate_finalizes == 2
            ):
                raise failure
        handle = real_finalize(value, callback, *args, **kwargs)
        if value is candidate:
            if detach_failure is not None:
                handle = FailingDetachHandle(handle, detach_failure)
            observed_handles.append(handle)
        return handle

    patch.setattr(continuous, "fields", discover_fields)
    patch.setattr(store, "_metadata_fingerprint", fingerprint)
    patch.setattr(continuous, "finalize", register_finalizer)
    return observed_handles


@pytest.mark.parametrize("stage", ["fields", "fingerprint", "first_finalize", "second_finalize"])
@pytest.mark.parametrize("reissue", [False, True], ids=["new", "reissue"])
@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
def test_failed_issuance_restores_only_candidate_entries_and_retires_created_handles(
    monkeypatch, stage, reissue, error_type
):
    store = isolated_store()
    earlier = store._own(compact_index(store, "earlier"))
    candidate = compact_index(store, "candidate")
    if reissue:
        store._own(candidate)
    earlier_entries = entries_for(store, earlier)
    prior_entries = entries_for(store, candidate)
    failure = error_type("selected ownership issuance failure")

    with monkeypatch.context() as patch:
        handles = inject_issuance_failure(patch, store, candidate, stage, failure)
        with pytest.raises(error_type) as raised:
            store._own(candidate)
    assert raised.value is failure
    assert_entries_unchanged(store, candidate, prior_entries)
    assert_entries_unchanged(store, earlier, earlier_entries)
    store._require(earlier, ResolvedContinuousIndex)
    if reissue:
        store._require(candidate, ResolvedContinuousIndex)
    assert all(not handle.alive for handle in handles)

    # Manually invoking an abort-created retired handle must have no effect,
    # including after a later successful issuance of the still-live same value.
    for handle in handles:
        handle()
    assert_entries_unchanged(store, candidate, prior_entries)
    assert store._own(candidate) is candidate
    for handle in handles:
        handle()
    store._require(candidate, ResolvedContinuousIndex)
    store._require(earlier, ResolvedContinuousIndex)
    assert_entries_unchanged(store, earlier, earlier_entries)


def test_successful_issuance_cleans_actual_weak_entries_when_value_is_collected():
    store = isolated_store()
    earlier = store._own(compact_index(store, "earlier"))
    earlier_entries = entries_for(store, earlier)
    candidate = compact_index(store, "collectible")
    key, weak = id(candidate), ref(candidate)
    assert store._own(candidate) is candidate
    store._require(candidate, ResolvedContinuousIndex)
    del candidate
    gc.collect()
    assert weak() is None
    for mapping in (store._owned, store._owned_fields, store._metadata_fingerprints):
        assert key not in mapping
    store._require(earlier, ResolvedContinuousIndex)
    assert_entries_unchanged(store, earlier, earlier_entries)


def test_successful_same_value_reissuance_remains_owned_and_collectible():
    store = isolated_store()
    candidate = compact_index(store, "same-value")
    key, weak = id(candidate), ref(candidate)
    assert store._own(candidate) is candidate
    store._require(candidate, ResolvedContinuousIndex)
    assert store._own(candidate) is candidate
    store._require(candidate, ResolvedContinuousIndex)
    assert store._owned[key] is candidate
    assert len(store._owned_fields) == len(store._metadata_fingerprints) == 1
    del candidate
    gc.collect()
    assert weak() is None
    assert key not in store._owned
    assert key not in store._owned_fields
    assert key not in store._metadata_fingerprints


def test_changed_compact_metadata_is_rejected_by_original_fingerprint_guard():
    store = isolated_store()
    earlier = store._own(compact_index(store, "earlier"))
    earlier_entries = entries_for(store, earlier)
    candidate = store._own(compact_index(store, "mutable"))
    store._require(candidate, ResolvedContinuousIndex)
    candidate.snapshot.row["label"] = "changed"
    with pytest.raises(ContinuousAccountConflict, match=r"^OWNED_CONTINUOUS_VALUE_CHANGED$"):
        store._require(candidate, ResolvedContinuousIndex)
    store._require(earlier, ResolvedContinuousIndex)
    assert_entries_unchanged(store, earlier, earlier_entries)


@pytest.mark.parametrize("reissue", [False, True], ids=["new", "reissue"])
def test_fingerprint_failure_preserves_reentrant_unrelated_issuance(monkeypatch, reissue):
    store = isolated_store()
    earlier = store._own(compact_index(store, "earlier"))
    candidate = compact_index(store, "candidate")
    unrelated = compact_index(store, "unrelated")
    if reissue:
        store._own(candidate)
    earlier_entries = entries_for(store, earlier)
    prior_entries = entries_for(store, candidate)
    issued = []
    failure = RuntimeError("fingerprint failed after unrelated issuance")

    def reenter():
        assert store._own(unrelated) is unrelated
        issued.append(entries_for(store, unrelated))

    with monkeypatch.context() as patch:
        handles = inject_issuance_failure(
            patch, store, candidate, "fingerprint", failure, reenter=reenter
        )
        with pytest.raises(RuntimeError) as raised:
            store._own(candidate)
    assert raised.value is failure
    assert issued
    assert_entries_unchanged(store, candidate, prior_entries)
    assert_entries_unchanged(store, unrelated, issued[-1])
    assert_entries_unchanged(store, earlier, earlier_entries)
    store._require(unrelated, ResolvedContinuousIndex)
    store._require(earlier, ResolvedContinuousIndex)
    if reissue:
        store._require(candidate, ResolvedContinuousIndex)
    assert all(not handle.alive for handle in handles)


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
def test_issuance_and_detach_failures_are_grouped_after_all_registry_restoration(
    monkeypatch, error_type
):
    store = isolated_store()
    earlier = store._own(compact_index(store, "earlier"))
    candidate = compact_index(store, "candidate")
    earlier_entries = entries_for(store, earlier)
    prior_entries = entries_for(store, candidate)
    failure = error_type("second finalizer registration failed")
    cleanup = RuntimeError("first handle detached but cleanup reporting failed")

    with monkeypatch.context() as patch:
        handles = inject_issuance_failure(
            patch, store, candidate, "second_finalize", failure, detach_failure=cleanup
        )
        try:
            with pytest.raises(BaseExceptionGroup) as raised:
                store._own(candidate)
        except KeyboardInterrupt as ungrouped:
            if ungrouped is not failure:
                raise
            pytest.fail("injected issuance interruption escaped without the cleanup group")
    assert len(raised.value.exceptions) == 2
    assert raised.value.exceptions[0] is failure and raised.value.exceptions[1] is cleanup
    assert raised.value.__cause__ is None and raised.value.__suppress_context__ is True
    assert_entries_unchanged(store, candidate, prior_entries)
    assert_entries_unchanged(store, earlier, earlier_entries)
    store._require(earlier, ResolvedContinuousIndex)
    assert handles and all(not handle.alive for handle in handles)
    assert store._own(candidate) is candidate
    for handle in handles:
        handle()
    store._require(candidate, ResolvedContinuousIndex)
    assert_entries_unchanged(store, earlier, earlier_entries)
