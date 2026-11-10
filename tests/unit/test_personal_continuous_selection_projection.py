"""Literal retained-metadata projection, without SQL, clock or access authority."""

import json
from dataclasses import asdict, replace
from datetime import UTC, datetime

import pytest

from apps.api.continuous_selection_projection import continuous_selection_response
from apps.api.contracts import ContinuousSelectionResponse
from packages.domain.continuous_selection_contracts import (
    ContinuousSelectionCheckpoint,
    ContinuousSelectionSnapshot,
    RetainedContinuousSelection,
)

_ACCOUNT = "projection-account"
_CHECKPOINT_TIME = datetime(2026, 11, 2, 0, 0, 0, 123456, tzinfo=UTC)
_RECORDED_TIME = datetime(2026, 11, 1, 23, 59, 58, 654321, tzinfo=UTC)
_EFFECTIVE_TIME = datetime(2026, 11, 2, 0, 0, 1, 7, tzinfo=UTC)


def _selected(counter=1, *, enabled=False):
    return ContinuousSelectionSnapshot(
        account_id=_ACCOUNT,
        state="selected",
        checkpoint=ContinuousSelectionCheckpoint("projection-stream", counter, _CHECKPOINT_TIME),
        selection=RetainedContinuousSelection(
            generation=counter,
            strategy_name="recorded-strategy",
            strategy_version="engineering/1",
            configuration_sha256="a" * 64,
            instrument_symbols=(("instrument-a-spy", "SPY"), ("instrument-z-qqq", "QQQ")),
            policy_id="recorded-policy",
            enabled_for_new_exposure=enabled,
            live_authorized=False,
            recorded_at=_RECORDED_TIME,
            effective_at=_EFFECTIVE_TIME,
        ),
    )


@pytest.mark.parametrize("state", ["absent", "unselected"])
def test_original_absent_and_unselected_null_shapes_are_literal(state):
    checkpoint = (
        None
        if state == "absent"
        else ContinuousSelectionCheckpoint("projection-stream", 1, _CHECKPOINT_TIME)
    )
    snapshot = ContinuousSelectionSnapshot(_ACCOUNT, state, checkpoint, None)
    before = asdict(snapshot)
    result = continuous_selection_response(snapshot, account_id=_ACCOUNT)
    assert type(result) is ContinuousSelectionResponse
    assert json.loads(result.model_dump_json()) == {
        "account_id": "projection-account",
        "state": state,
        "checkpoint": None
        if state == "absent"
        else {
            "stream_id": "projection-stream",
            "sequence": "1",
            "recorded_at": "2026-11-02T00:00:00.123456Z",
        },
        "selection": None,
        "verification": "row_integrity_only",
    }
    assert snapshot.checkpoint is checkpoint and snapshot.selection is None
    assert asdict(snapshot) == before


@pytest.mark.parametrize(
    "counter,wire_counter",
    [
        (1, "1"),
        (9007199254740993, "9007199254740993"),
        (9223372036854775807, "9223372036854775807"),
    ],
)
def test_selected_literal_wire_preserves_native_counters_order_and_original_utc(
    counter, wire_counter
):
    snapshot = _selected(counter)
    checkpoint, selection = snapshot.checkpoint, snapshot.selection
    before = asdict(snapshot)
    result = continuous_selection_response(snapshot, account_id=_ACCOUNT)
    assert type(result) is ContinuousSelectionResponse
    assert type(result.checkpoint.sequence) is type(result.selection.generation) is int
    assert result.checkpoint.sequence == result.selection.generation == counter
    assert result.checkpoint.recorded_at == _CHECKPOINT_TIME
    assert result.selection.recorded_at == _RECORDED_TIME
    assert result.selection.effective_at == _EFFECTIVE_TIME
    # Independent wire facts, including every key: no health, owner-history,
    # financial-state or permission field is added to the retained row view.
    assert json.loads(result.model_dump_json()) == {
        "account_id": "projection-account",
        "state": "selected",
        "checkpoint": {
            "stream_id": "projection-stream",
            "sequence": wire_counter,
            "recorded_at": "2026-11-02T00:00:00.123456Z",
        },
        "selection": {
            "generation": wire_counter,
            "strategy_name": "recorded-strategy",
            "strategy_version": "engineering/1",
            "configuration_sha256": (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            "instruments": [
                {"instrument_id": "instrument-a-spy", "symbol": "SPY"},
                {"instrument_id": "instrument-z-qqq", "symbol": "QQQ"},
            ],
            "policy_id": "recorded-policy",
            "enabled_for_new_exposure": False,
            "live_authorized": False,
            "recorded_at": "2026-11-01T23:59:58.654321Z",
            "effective_at": "2026-11-02T00:00:01.000007Z",
        },
        "verification": "row_integrity_only",
    }
    assert snapshot.checkpoint is checkpoint and snapshot.selection is selection
    assert checkpoint.recorded_at is _CHECKPOINT_TIME
    assert selection.recorded_at is _RECORDED_TIME and selection.effective_at is _EFFECTIVE_TIME
    assert asdict(snapshot) == before


def test_retained_enabled_flag_is_preserved_without_changing_live_or_verification_scope():
    snapshot = _selected(enabled=True)
    before = asdict(snapshot)
    result = continuous_selection_response(snapshot, account_id=_ACCOUNT)
    assert result.selection.enabled_for_new_exposure is True
    assert result.selection.live_authorized is False
    assert result.verification == "row_integrity_only"
    assert asdict(snapshot) == before


def test_original_counter_serialization_schema_remains_string():
    result = continuous_selection_response(_selected(), account_id=_ACCOUNT)
    schema = type(result).model_json_schema(mode="serialization")
    for name, field in (
        ("ContinuousSelectionCheckpointView", "sequence"),
        ("RetainedContinuousSelectionView", "generation"),
    ):
        counter = schema["$defs"][name]["properties"][field]
        assert counter["type"] == "string"
        assert counter["pattern"] == r"^[1-9][0-9]{0,18}$"
    assert set(schema["properties"]) == {
        "account_id",
        "state",
        "checkpoint",
        "selection",
        "verification",
    }


@pytest.mark.parametrize(
    "snapshot",
    [None, {"account_id": _ACCOUNT, "state": "absent", "checkpoint": None, "selection": None}],
)
def test_non_snapshot_objects_raise_the_original_type_error_without_dto_coercion(snapshot):
    with pytest.raises(TypeError) as raised:
        continuous_selection_response(snapshot, account_id=_ACCOUNT)
    assert type(raised.value) is TypeError
    assert str(raised.value) == "continuous selection returned a conflicting snapshot"


def test_original_foreign_account_guard_runs_before_domain_revalidation():
    snapshot = replace(_selected(), account_id="another-actual-account")
    # This would fail the original domain gate if the earlier account guard were
    # skipped or the requested account silently adopted from the returned value.
    object.__setattr__(snapshot, "verification", "ready")
    with pytest.raises(TypeError) as raised:
        continuous_selection_response(snapshot, account_id=_ACCOUNT)
    assert type(raised.value) is TypeError
    assert str(raised.value) == "continuous selection returned a conflicting snapshot"
    assert snapshot.account_id == "another-actual-account" and snapshot.verification == "ready"


@pytest.mark.parametrize(
    "mutation,message",
    [
        ("verification", "continuous selection verification scope is invalid"),
        ("sequence", "continuous selection metadata counter is outside native bounds"),
    ],
)
def test_original_domain_revalidation_rejects_mutated_records_before_projection(mutation, message):
    snapshot = _selected()
    # Start with a valid original nested record, then change exactly one leaf.
    snapshot.__post_init__()
    if mutation == "verification":
        object.__setattr__(snapshot, "verification", "ready")
    else:
        object.__setattr__(snapshot.checkpoint, "sequence", 0)
    before = asdict(snapshot)
    with pytest.raises(ValueError) as raised:
        continuous_selection_response(snapshot, account_id=_ACCOUNT)
    assert type(raised.value) is ValueError
    assert str(raised.value) == message
    assert asdict(snapshot) == before
