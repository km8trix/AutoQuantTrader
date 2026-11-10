"""Actual SQL/fence captures with explicit synthetic assignment fixture authority.

These tests qualify comparison inputs only. The fixed factory keeps its own
signed-history, source, Stop and final SQL/fence guards before returning bytes.
"""

from copy import copy
from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.persistence.daily_runtime_risk import DailyRuntimeRiskConflict
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignments
from packages.persistence.schema import phase5_operational_control_heads
from tests.integration.test_sql_daily_runtime_risk import (
    _write_transaction,
)
from tests.integration.test_sql_daily_runtime_risk import (
    harness as harness,
)


def _fresh(harness):
    return harness.store.read_snapshot(account_id=harness.account, fence=harness.lease.fence)


def test_daily_complete_capture_keeps_actual_fresh_receipt_without_replay(harness, monkeypatch):
    original = harness.resolved()
    original_receipt = original.raw.receipt
    harness.clock.instant += timedelta(microseconds=1)
    fresh = _fresh(harness)
    assert fresh.receipt is not original_receipt
    assert fresh.receipt.validated_at > original_receipt.validated_at
    assert fresh.capture_usage == original.raw.capture_usage

    def forbidden(*args, **kwargs):
        pytest.fail("comparison must not resolve, encode, decode or read producer objects")

    with monkeypatch.context() as guard:
        guard.setattr(harness.store, "resolve_snapshot", forbidden)
        guard.setattr(harness.reader, "resolve", forbidden)
        guard.setattr(codec, "encode_record", forbidden)
        guard.setattr(codec, "decode_record", forbidden)
        assert harness.store.require_same_complete_capture(original, fresh) is None
    assert original.raw.receipt is original_receipt
    harness.store.require_resolved_snapshot(original)


@pytest.mark.parametrize(
    "fault",
    (
        "raw_copy",
        "receipt_copy",
        "receipt_time",
        "fence_owner",
        "fence_generation",
        "tables",
        "usage",
    ),
)
def test_daily_complete_capture_rejects_original_field_and_receipt_changes(harness, fault):
    original = harness.resolved()
    fresh = _fresh(harness)
    selected = fresh
    undo = None
    if fault == "raw_copy":
        selected = replace(fresh)
    else:
        target, name, changed = (
            (fresh, "receipt", copy(fresh.receipt))
            if fault == "receipt_copy"
            else (
                fresh.receipt,
                "validated_at",
                fresh.receipt.validated_at + timedelta(microseconds=1),
            )
            if fault == "receipt_time"
            else (fresh.receipt.fence, "owner_id", "changed-owner")
            if fault == "fence_owner"
            else (
                fresh.receipt.fence,
                "fencing_generation",
                fresh.receipt.fence.fencing_generation + 1,
            )
            if fault == "fence_generation"
            else (fresh, "tables", tuple(list(fresh.tables)))
            if fault == "tables"
            else (fresh, "capture_usage", tuple(list(fresh.capture_usage)))
        )
        undo = target, name, getattr(target, name)
        assert changed is not undo[2]
        object.__setattr__(target, name, changed)
    try:
        with pytest.raises(DailyRuntimeRiskConflict, match=r"original|capture"):
            harness.store.require_same_complete_capture(original, selected)
    finally:
        if undo is not None:
            object.__setattr__(*undo)
    harness.store.require_same_complete_capture(original, fresh)


@pytest.mark.parametrize("kind", ("assignment_row", "control_head"))
def test_daily_complete_capture_rejects_fresh_current_row_changes(harness, kind):
    original = harness.resolved()
    table = (
        daily_runtime_assignments if kind == "assignment_row" else phase5_operational_control_heads
    )
    column = "command_payload" if kind == "assignment_row" else "canonical_payload"
    # The changed row is copied by the actual fresh reader; no resolver or
    # ownership registration is substituted to make a synthetic passing result.
    with _write_transaction(harness.engine) as connection:
        old = connection.execute(
            sa.select(table.c[column]).where(table.c.account_id == harness.account)
        ).scalar_one()
        changed = old[:-1] + (b"]" if type(old) is bytes else "]")
        updated = connection.execute(
            sa.update(table).where(table.c.account_id == harness.account).values({column: changed})
        )
        assert updated.rowcount == 1 and old != changed and len(old) == len(changed)
    fresh = _fresh(harness)
    with pytest.raises(ValueError, match=r"CAPTURE|capture"):
        harness.store.require_same_complete_capture(original, fresh)


def test_daily_complete_capture_rejects_a_real_mutation_read_profile(harness):
    original = harness.resolved()
    fresh = harness.store.read_snapshot(
        account_id=harness.account, fence=harness.lease.fence, command_id="mutation-selection"
    )
    with pytest.raises(DailyRuntimeRiskConflict, match="complete factory"):
        harness.store.require_same_complete_capture(original, fresh)
