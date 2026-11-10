"""Compare actual owned descriptor captures, including private SQL evidence."""

from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa

from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.daily_runtime_risk import RuntimeReadBudget
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.schema import phase2_account_leases
from tests.integration.test_continuous_runtime_attempt_sources import (
    attempt_case as attempt_case,
)
from tests.integration.test_runtime_historical_descriptor import (
    original_activation as original_activation,
)


def capture_again(case, producer, plan):
    with case.store.write_transaction() as connection:
        return producer.capture_historical_descriptor_in_transaction(
            connection, plan, budget=RuntimeReadBudget()
        )


def compare(producer, old, fresh):
    return producer.require_same_historical_capture(
        old, fresh, comparison=ContinuousCaptureComparison()
    )


def test_actual_historical_capture_comparison_avoids_codec_hash_and_replay(
    original_activation, monkeypatch
):
    case, producer, _reader, _source, fresh_descriptor, original = original_activation
    plan = producer.prepare_historical_descriptor(fresh_descriptor.plan.reference)
    fresh = capture_again(case, producer, plan)
    assert fresh is not original.snapshot and plan is not original.snapshot.plan
    assert fresh.canonical and fresh.markets
    reached = []
    clock_checks = []
    original_clock_guard = producer.require_original_clock

    def forbidden(*args, **kwargs):
        pytest.fail("raw comparison must not repeat original source content validation or replay")

    def original_clock_fields(value, *, deep=True):
        assert deep is False
        original_clock_guard(value, deep=False)
        clock_checks.append(value)

    with monkeypatch.context() as guarded:
        for owner, names in (
            (producer.codec, ("encode_record", "decode_record")),
            (producer.artifacts, ("read",)),
            (case.store, ("restore", "resolve_reference")),
            (case.h.store, ("read_snapshot", "resolve_snapshot")),
            (producer, ("resolve_historical_descriptor",)),
            (producer._history_reader(), ("require_plan", "require_historical_descriptor")),
            (producer.forward_sources, ("require_resolved",)),
        ):
            for name in names:
                guarded.setattr(owner, name, forbidden)
        guarded.setattr(producer, "require_original_clock", original_clock_fields)
        assert compare(producer, original.snapshot, fresh) is None
        reached.append("complete descriptor capture compared")
    assert reached == ["complete descriptor capture compared"]
    assert all(
        any(checked is value for checked in clock_checks)
        for value in (
            old_clock
            for p in (original.snapshot.plan, plan)
            for old_clock in (p.clock, p.quote_clock)
        )
    )
    producer.require_historical_descriptor(original)


def test_actual_owned_descriptor_capture_detects_private_journal_and_source_lease_rows(
    original_activation,
):
    case, producer, _reader, _source, _fresh, original = original_activation
    old = original.snapshot
    changes = [
        (
            name,
            sa.update(journal_entries)
            .where(
                journal_entries.c.record_id
                == getattr(old, name).requested_receipt.entries[0]["record_id"]
            )
            .values(payload=b"{}"),
        )
        for name in ("descriptor", "clock", "quote_clock")
    ]
    lease = original.canonical[0].source_lease
    assert lease is not None
    changes.append(
        (
            "original_source_lease",
            sa.update(phase2_account_leases)
            .where(
                phase2_account_leases.c.account_id == case.scope.account_id,
                phase2_account_leases.c.lease_id == lease.lease_id,
                phase2_account_leases.c.revision_number == lease.revision_number,
            )
            .values(expires_at=lease.expires_at + timedelta(seconds=1)),
        )
    )
    reached = []

    class RollbackCapture(Exception):
        pass

    for name, statement in changes:
        with pytest.raises(RollbackCapture), case.store.write_transaction() as connection:
            assert connection.execute(statement).rowcount == 1
            changed = producer.capture_historical_descriptor_in_transaction(
                connection, old.plan, budget=RuntimeReadBudget()
            )
            assert changed.plan is old.plan
            raise RollbackCapture
        # The raw is genuinely owned and the SQL modification has rolled back.
        # Comparing full private captured rows must still detect its difference.
        with pytest.raises(ValueError):
            compare(producer, old, changed)
        reached.append(name)
        restored = capture_again(case, producer, old.plan)
        assert compare(producer, old, restored) is None
    assert reached == ["descriptor", "clock", "quote_clock", "original_source_lease"]
    producer.require_historical_descriptor(original)


def test_actual_descriptor_comparison_rejects_copied_raw_and_plan(original_activation):
    case, producer, _reader, _source, _fresh, original = original_activation
    old = original.snapshot
    fresh = capture_again(case, producer, old.plan)
    assert compare(producer, old, fresh) is None
    for copied in (replace(old), replace(fresh)):
        with pytest.raises(ValueError):
            compare(producer, old, copied)
    original_plan = fresh.plan
    try:
        object.__setattr__(fresh, "plan", replace(original_plan))
        with pytest.raises(ValueError):
            compare(producer, old, fresh)
    finally:
        object.__setattr__(fresh, "plan", original_plan)
    assert compare(producer, old, fresh) is None
