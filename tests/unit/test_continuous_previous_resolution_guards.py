"""Invalid original previous values reject before decode and capture planning.

The imported fixture uses real public resolver/value/ownership methods but a
constructor-free store, controlled decoded rows and opaque metadata fingerprints.
Checkpoint/request values are synthetic SimpleNamespaces. These tests qualify
guard ordering and original identity, not authenticated account/record content,
SQL, leases, composition, financial correctness or ownership lifetime.
"""

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from packages.persistence.continuous_account import (
    ContinuousAccountConflict,
    ContinuousIndexSnapshot,
    ResolvedContinuousIndex,
)
from tests.unit.test_continuous_index_plan_contract import admitted_index as admitted_index


def current_resolution(case, endpoint, previous):
    if endpoint == "index":
        return case.store.resolve_index(
            ContinuousIndexSnapshot(case.snapshot.scope, case.snapshot.row), previous=previous
        )
    return case.store.resolve_snapshot(case.snapshot, previous=previous)


def observe_current_decode(monkeypatch, case):
    decode = Mock(wraps=case.store._decode_reference_row)
    monkeypatch.setattr(case.store, "_decode_reference_row", decode)
    # Fixture admission already succeeded; observe only the selected current call.
    case.planner.previous_arguments.clear()
    return decode


def assert_original_registry_entries_preserved(case, *, no_new_entries):
    if no_new_entries:
        assert set(case.store._owned) == set(case.registrations)
        assert set(case.store._owned_fields) == set(case.registrations)
        assert set(case.store._metadata_fingerprints) == set(case.registrations)
    for identity, (value, fields, fingerprint) in case.registrations.items():
        assert case.store._owned[identity] is value
        assert case.store._owned_fields[identity] is fields
        assert case.store._metadata_fingerprints[identity] is fingerprint
    # A deliberately changed original previous value is invalid. Do not turn
    # registry preservation into a claim that its mutated content remains owned.


@pytest.mark.parametrize("endpoint", ["index", "snapshot"])
@pytest.mark.parametrize(
    ("invalid", "expected"),
    [
        ("unregistered_copy", "OWNED_CONTINUOUS_VALUE_REQUIRED"),
        ("checkpoint_field", "OWNED_CONTINUOUS_VALUE_CHANGED"),
        ("checkpoint_digest", "OWNED_RESTORED_ENGINE_CONTENT_CHANGED"),
        ("request_digest", "OWNED_RESTORED_ENGINE_CONTENT_CHANGED"),
    ],
)
def test_invalid_previous_rejects_before_decode_planning_or_later_work(
    admitted_index, monkeypatch, endpoint, invalid, expected
):
    case = admitted_index
    decode = observe_current_decode(monkeypatch, case)
    previous = case.previous
    if invalid == "unregistered_copy":
        previous = replace(previous)
        assert previous is not case.previous
    elif invalid == "checkpoint_field":
        original_checkpoint = previous.checkpoint
        replacement = SimpleNamespace(**vars(original_checkpoint))
        assert replacement is not original_checkpoint
        assert vars(replacement) == vars(original_checkpoint)
        object.__setattr__(previous, "checkpoint", replacement)
    elif invalid == "checkpoint_digest":
        previous.checkpoint.semantic_sha256 = "f" * 64
    else:
        previous.request.semantic_sha256 = "f" * 64

    with pytest.raises(ContinuousAccountConflict, match="^" + expected + "$"):
        current_resolution(case, endpoint, previous)
    decode.assert_not_called()
    assert case.planner.previous_arguments == []
    for boundary in case.boundaries:
        boundary.assert_not_called()
    assert_original_registry_entries_preserved(case, no_new_entries=True)


@pytest.mark.parametrize("endpoint", ["index", "snapshot"])
def test_valid_original_previous_reaches_current_resolution_boundary(
    admitted_index, monkeypatch, endpoint
):
    case = admitted_index
    decode = observe_current_decode(monkeypatch, case)
    if endpoint == "index":
        result = current_resolution(case, endpoint, case.previous)
        assert type(result) is ResolvedContinuousIndex
        assert result.composition_plan is case.planner.result
        assert result.receipt is case.earlier.receipt
        case.store._require(result, ResolvedContinuousIndex)
        for boundary in case.boundaries:
            boundary.assert_not_called()
    else:
        lease = case.boundaries[0]
        with pytest.raises(AssertionError) as raised:
            current_resolution(case, endpoint, case.previous)
        assert raised.value is lease.side_effect
        lease.assert_called()
        for boundary in case.boundaries[1:]:
            boundary.assert_not_called()
    decode.assert_called()
    assert case.planner.previous_arguments
    assert all(value is case.previous for value in case.planner.previous_arguments)
    assert_original_registry_entries_preserved(case, no_new_entries=False)
