"""Original activation sources preserve their evidence without granting fresh authority."""

from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa

from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication
from packages.persistence.daily_runtime_risk import RuntimeReadBudget
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.schema import phase2_account_leases
from tests.integration.test_continuous_runtime_attempt_sources import (
    activation_preparation,
)
from tests.integration.test_continuous_runtime_attempt_sources import (
    attempt_case as attempt_case,
)


@pytest.fixture
def original_activation(attempt_case):
    case, producer, reader, _previous, _current, admission, source, fresh = activation_preparation(
        attempt_case
    )
    plan = reader.prepare_attempt_source_read((source.reference,))
    with case.store.write_transaction() as connection:
        captured = reader.capture_attempt_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )
    prefix = reader.resolve_original_prefix(
        captured,
        source_reference=source.reference,
        admissions=(admission,),
        assignment_sha256=fresh.plan.descriptor.assignment_sha256,
        control_sha256=fresh.plan.descriptor.control_sha256,
    )
    original = producer.resolve_historical_descriptor(captured.state.descriptors[0], prefix=prefix)
    return case, producer, reader, source, fresh, original


def test_original_activation_descriptor_matches_actual_retained_receipt_and_times(
    original_activation, monkeypatch
):
    case, producer, _reader, source, fresh, original = original_activation
    producer.require_historical_descriptor(original)
    assert original.receipt == fresh.descriptor.receipt == source.closure.descriptor_receipt
    assert original.context.descriptor == fresh.plan.descriptor
    assert original.context.operating.clock == fresh.plan.operating.clock
    assert original.context.quote_clock == fresh.plan.quote_clock.observation
    assert original.context.descriptor.original_checked_at == source.source.checked_at
    assert original.context.checkpoint.now < source.source.checked_at
    assert original.context.quote_clock.observed_at_utc < source.source.checked_at

    # Publish the actual dispatch through the C/B owner, then keep the original
    # descriptor as immutable evidence while the legitimate current head advances.
    raw = case.h.store.read_attempt_snapshot(
        account_id=case.scope.account_id, fence=case.h.lease.fence, envelopes=source.envelopes
    )
    actual = case.h.store.resolve_snapshot(raw)
    mutation = case.h.store.prepare_attempt_mutation(
        actual, dispatch_journal=_reader.dispatch_journal, dispatch_appends=source.dispatch_appends
    )
    transition = case.owner.prepare_runtime_action(
        command_id=source.source.coordinator_command_id,
        checkpoint=source.previous.checkpoint,
        action=source.action,
    )
    account = case.store.prepare(
        transition,
        scope=case.scope,
        previous=source.previous,
        source_evidence=source.reference,
        attempts=mutation,
    )
    completed = SqlContinuousAttemptPublication(account=case.store).publish_dispatch(
        account, fence=case.h.lease.fence
    )
    assert completed.receipt.commit.sequence == original.canonical[0].receipt.commit.sequence + 1
    with case.store.write_transaction() as connection:
        producer.recheck_historical_descriptor_in_transaction(connection, original)

    def forbidden(*args, **kwargs):
        raise AssertionError("historical sources must not restore current C/B or renew the clock")

    monkeypatch.setattr(case.store, "restore", forbidden)
    monkeypatch.setattr(case.h.store, "read_snapshot", forbidden)
    monkeypatch.setattr(case.h.store, "resolve_snapshot", forbidden)
    monkeypatch.setattr(type(producer.operating.clock_sampler), "require_current", forbidden)
    case.h.clock.instant += timedelta(hours=1)
    again_plan = producer.prepare_historical_descriptor(fresh.plan.reference)
    with case.store.write_transaction() as connection:
        raw = producer.capture_historical_descriptor_in_transaction(
            connection, again_plan, budget=RuntimeReadBudget()
        )
    again = producer.resolve_historical_descriptor(raw, prefix=original.prefix)
    assert again.receipt == original.receipt
    assert again.context == original.context
    with case.store.write_transaction() as connection:
        producer.recheck_historical_descriptor_in_transaction(connection, again)


def test_original_activation_descriptor_rejects_copies_and_mutated_nested_sources(
    original_activation,
):
    _case, producer, _reader, _source, _fresh, original = original_activation
    with pytest.raises(ValueError, match="OWNED_HISTORICAL"):
        producer.require_historical_descriptor(replace(original))
    descriptor = original.snapshot.plan.descriptor
    original_time = descriptor.original_checked_at
    try:
        object.__setattr__(descriptor, "original_checked_at", original_time + timedelta(seconds=1))
        with pytest.raises(ValueError, match="ORIGINAL_HISTORICAL"):
            producer.require_historical_descriptor(original)
    finally:
        object.__setattr__(descriptor, "original_checked_at", original_time)
    producer.require_historical_descriptor(original)


def test_original_activation_sql_recheck_rejects_changed_original_journal(
    original_activation, monkeypatch
):
    case, producer, _reader, _source, _fresh, original = original_activation

    def forbidden(*args, **kwargs):
        raise AssertionError("final original source recheck must remain compact SQL")

    monkeypatch.setattr(producer.codec, "encode_record", forbidden)
    monkeypatch.setattr(producer.codec, "decode_record", forbidden)
    monkeypatch.setattr(producer.artifacts, "read", forbidden)
    with case.store.write_transaction() as connection:
        producer.recheck_historical_descriptor_in_transaction(connection, original)
    changes = [
        sa.update(journal_entries)
        .where(journal_entries.c.record_id.in_(receipt.record_ids))
        .values(payload=b"{}")
        for receipt in (
            original.receipt,
            original.snapshot.plan.clock.reference.receipt,
            original.snapshot.plan.quote_clock.reference.receipt,
        )
    ]
    canonical = original.canonical[0]
    lease = canonical.source_lease
    changes.extend(
        (
            sa.update(continuous_account_commits)
            .where(
                continuous_account_commits.c.account_id == case.scope.account_id,
                continuous_account_commits.c.sequence == canonical.receipt.commit.sequence,
            )
            .values(receipt_sha256="f" * 64),
            sa.update(phase2_account_leases)
            .where(
                phase2_account_leases.c.account_id == case.scope.account_id,
                phase2_account_leases.c.lease_id == lease.lease_id,
                phase2_account_leases.c.revision_number == lease.revision_number,
            )
            .values(expires_at=lease.expires_at + timedelta(seconds=1)),
        )
    )
    for statement in changes:
        with pytest.raises(ValueError), case.store.write_transaction() as connection:
            changed = connection.execute(statement)
            assert changed.rowcount == 1
            producer.recheck_historical_descriptor_in_transaction(connection, original)


def test_original_activation_capture_enforces_shared_budget(original_activation):
    case, producer, _reader, _source, fresh, _original = original_activation
    plan = producer.prepare_historical_descriptor(fresh.plan.reference)
    with pytest.raises(ValueError), case.store.write_transaction() as connection:
        producer.capture_historical_descriptor_in_transaction(
            connection,
            plan,
            budget=RuntimeReadBudget(payload_bytes=32 * 1024 * 1024),
        )
