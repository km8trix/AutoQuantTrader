"""Public snapshot resolution revalidates the current capture-planning boundary.

These are isolated guard regressions, not authenticated restore acceptance. A real
store instance uses the original public methods, value types and weak ownership
registry. Row decoding and metadata fingerprints supply controlled synthetic
values; no database, artifacts, genuine account/lease or composition is resolved.
The original integration, lease, financial and concurrency tests remain required.
"""

from types import SimpleNamespace
from unittest.mock import Mock
from weakref import WeakValueDictionary

import pytest

from packages.persistence import continuous_account as continuous
from packages.persistence.continuous_account import (
    ContinuousAccountConflict,
    ContinuousAccountSnapshot,
    ContinuousCompositionPlan,
    ContinuousCompositionSnapshot,
    ContinuousIndexSnapshot,
    ResolvedContinuousAccount,
    ResolvedContinuousComposition,
    ResolvedContinuousIndex,
    SqlContinuousAccount,
)


class PlanSubclass(ContinuousCompositionPlan):
    """Matching fields and inheritance do not satisfy the exact plan type guard."""


class ChangingPlanner:
    def __init__(self, result):
        self.result = result
        self.failure = None
        self.previous_arguments = []
        self.resolve = Mock(side_effect=AssertionError("composition resolution reached"))
        self.capture_in_transaction = Mock(
            side_effect=AssertionError("composition capture reached")
        )

    def prepare_capture(self, commit, *, previous):
        self.previous_arguments.append(previous)
        if self.failure is not None:
            raise self.failure
        return self.result


@pytest.fixture
def admitted_index(monkeypatch):
    # Avoid opening any engine or creating a coordinator/account. Retain the
    # original _own/_require/require_resolved methods and their identity registry.
    store = SqlContinuousAccount.__new__(SqlContinuousAccount)
    store._seal = object()
    store._owned = WeakValueDictionary()
    store._owned_fields = {}
    store._metadata_fingerprints = {}
    monkeypatch.setattr(store, "_metadata_fingerprint", lambda value: "unit-metadata")

    scope = object()
    prior_commit_digest = "a" * 64
    prior_checkpoint_digest = "b" * 64
    prior_request_digest = "c" * 64
    commit_digest = "d" * 64
    prior_commit = SimpleNamespace(
        scope=scope,
        sequence=1,
        semantic_sha256=prior_commit_digest,
        transition=SimpleNamespace(checkpoint_sha256=prior_checkpoint_digest),
        request=SimpleNamespace(semantic_sha256=prior_request_digest),
    )
    prior_snapshot = ContinuousAccountSnapshot(
        scope,
        {"commit_sha256": prior_commit_digest},
        None,
        ContinuousCompositionSnapshot(prior_commit_digest, None, store._seal),
        {},
    )
    previous = store._own(
        ResolvedContinuousAccount(
            prior_snapshot,
            SimpleNamespace(commit=prior_commit),
            SimpleNamespace(semantic_sha256=prior_checkpoint_digest),
            SimpleNamespace(semantic_sha256=prior_request_digest),
            None,
            ResolvedContinuousComposition(prior_commit_digest, None, store._seal),
            store._seal,
        )
    )
    commit = SimpleNamespace(
        scope=scope,
        sequence=2,
        semantic_sha256=commit_digest,
        previous_commit_sha256=prior_commit_digest,
        transition=SimpleNamespace(previous_checkpoint_sha256=prior_checkpoint_digest),
    )
    receipt = SimpleNamespace(commit=commit)
    row = {"commit_sha256": commit_digest, "canonical_payload": b"unit-decoded-row"}

    def decoded_reference(snapshot):
        assert type(snapshot) is ContinuousIndexSnapshot
        assert snapshot.scope is scope and snapshot.row == row
        return ContinuousIndexSnapshot(scope, dict(row)), receipt

    monkeypatch.setattr(store, "_decode_reference_row", decoded_reference)
    valid_plan = ContinuousCompositionPlan(commit_digest, object(), object())
    planner = ChangingPlanner(valid_plan)
    store.composer = planner

    lease = Mock(side_effect=AssertionError("lease validation reached"))
    monkeypatch.setattr(continuous, "_validate_lease", lease)
    journal = Mock(side_effect=AssertionError("journal resolution reached"))
    store.journal = SimpleNamespace(resolve_snapshot=journal)
    object_read = Mock(side_effect=AssertionError("artifact read reached"))
    store.artifacts = SimpleNamespace(read=object_read)
    connect = Mock(side_effect=AssertionError("SQL connection reached"))
    store.engine = SimpleNamespace(connect=connect)

    earlier = store.resolve_index(ContinuousIndexSnapshot(scope, row), previous=previous)
    assert type(earlier) is ResolvedContinuousIndex
    assert earlier.composition_plan is valid_plan and earlier.receipt is receipt
    store._require(earlier, ResolvedContinuousIndex)
    snapshot = ContinuousAccountSnapshot(
        scope,
        row,
        None,
        ContinuousCompositionSnapshot(commit_digest, None, object()),
        {},
    )
    registrations = {
        identity: (value, store._owned_fields[identity], store._metadata_fingerprints[identity])
        for identity, value in store._owned.items()
    }
    return SimpleNamespace(
        store=store,
        previous=previous,
        snapshot=snapshot,
        earlier=earlier,
        planner=planner,
        commit_digest=commit_digest,
        registrations=registrations,
        boundaries=(
            lease,
            journal,
            planner.resolve,
            planner.capture_in_transaction,
            object_read,
            connect,
        ),
    )


def assert_no_later_resolution_or_new_owned_index(case):
    for boundary in case.boundaries:
        boundary.assert_not_called()
    assert set(case.store._owned) == set(case.registrations)
    assert set(case.store._owned_fields) == set(case.registrations)
    assert set(case.store._metadata_fingerprints) == set(case.registrations)
    for identity, (value, fields, fingerprint) in case.registrations.items():
        assert case.store._owned[identity] is value
        assert case.store._owned_fields[identity] is fields
        assert case.store._metadata_fingerprints[identity] == fingerprint
    # Check the independent prior identity, not an arbitrary number of calls.
    assert case.planner.previous_arguments
    assert all(value is case.previous for value in case.planner.previous_arguments)
    case.store._require(case.earlier, ResolvedContinuousIndex)


def test_snapshot_with_current_valid_plan_reaches_lease_boundary(admitted_index):
    case = admitted_index
    lease = case.boundaries[0]
    with pytest.raises(AssertionError) as raised:
        case.store.resolve_snapshot(case.snapshot, previous=case.previous)
    assert raised.value is lease.side_effect
    lease.assert_called_once()
    for boundary in case.boundaries[1:]:
        boundary.assert_not_called()
    assert case.planner.previous_arguments
    assert all(value is case.previous for value in case.planner.previous_arguments)
    case.store._require(case.earlier, ResolvedContinuousIndex)


@pytest.mark.parametrize("invalid", ["duck_type", "subclass", "digest"])
def test_snapshot_rejects_current_bad_plan_after_an_earlier_valid_index(admitted_index, invalid):
    case = admitted_index
    if invalid == "duck_type":
        case.planner.result = SimpleNamespace(commit_sha256=case.commit_digest)
    elif invalid == "subclass":
        case.planner.result = PlanSubclass(case.commit_digest, object(), object())
    else:
        case.planner.result = ContinuousCompositionPlan("e" * 64, object(), object())
    with pytest.raises(ContinuousAccountConflict, match=r"^CONTINUOUS_RETAINED_INDEX_INVALID$"):
        case.store.resolve_snapshot(case.snapshot, previous=case.previous)
    assert_no_later_resolution_or_new_owned_index(case)


@pytest.mark.parametrize(
    "error_type", [ValueError, TypeError, KeyError, UnicodeError, ContinuousAccountConflict]
)
def test_snapshot_translates_current_planner_validation_failure(admitted_index, error_type):
    case = admitted_index
    failure = error_type("current planner rejected")
    case.planner.failure = failure
    with pytest.raises(
        ContinuousAccountConflict, match=r"^CONTINUOUS_RETAINED_INDEX_INVALID$"
    ) as raised:
        case.store.resolve_snapshot(case.snapshot, previous=case.previous)
    assert raised.value.__cause__ is None and raised.value.__suppress_context__ is True
    assert raised.value.__context__ is failure
    assert_no_later_resolution_or_new_owned_index(case)


@pytest.mark.parametrize("error_type", [RuntimeError, OSError])
def test_snapshot_preserves_current_planner_operational_failure(admitted_index, error_type):
    case = admitted_index
    failure = error_type("current planner failed")
    case.planner.failure = failure
    with pytest.raises(error_type) as raised:
        case.store.resolve_snapshot(case.snapshot, previous=case.previous)
    assert raised.value is failure
    assert_no_later_resolution_or_new_owned_index(case)
