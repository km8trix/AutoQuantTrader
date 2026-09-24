"""Original C publication/lease/journal metadata without recursive composition."""

from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.persistence.continuous_account import ContinuousAccountConflict
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.detached_journal_capture import DetachedJournalCapture
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.schema import phase2_account_leases
from tests.integration.test_continuous_account_store import Harness


@pytest.fixture
def h(tmp_path):
    value = Harness(tmp_path)
    value.publish(value.prepare())
    yield value
    value.engine.dispose()


def capture(h, command="initialize", **kwargs):
    with _repeatable_read_transaction(h.engine) as connection:
        return h.store.capture_reference_in_transaction(
            connection, scope=h.scope, command_id=command, **kwargs
        )


def forbidden(*args, **kwargs):
    raise AssertionError(
        "reference validation invoked composition, object I/O or recursive restore"
    )


def test_original_reference_validates_genesis_without_composer_or_checkpoint_read(h, monkeypatch):
    raw = capture(h)
    monkeypatch.setattr(h.composer, "prepare_capture", forbidden)
    monkeypatch.setattr(h.composer, "resolve", forbidden)
    monkeypatch.setattr(h.store, "restore", forbidden)
    monkeypatch.setattr(h.artifacts, "read", forbidden)
    value = h.store.resolve_reference(raw)
    h.store.require_reference(value)
    assert value.receipt.commit.sequence == 1
    assert value.previous_receipt is None and value.source_lease is None
    monkeypatch.setattr(codec, "encode_record", forbidden)
    monkeypatch.setattr(codec, "decode_record", forbidden)
    with _repeatable_read_transaction(h.engine) as connection:
        h.store.recheck_reference_in_transaction(connection, value)


def test_parent_reference_retains_original_source_lease_across_heartbeat_and_later_commit(h):
    previous = h.store.restore(h.scope)
    source_lease = previous.receipt.fence_reference.lease_sha256
    h.clock.advance(timedelta(seconds=1))
    renewed = h.coordinator.renew(h.fence)
    second = h.publish(h.next(previous))
    raw = capture(h, "next", source_lease_sha256=source_lease)
    value = h.store.resolve_reference(raw)
    assert value.receipt == second
    assert value.previous_receipt == previous.receipt
    assert value.receipt.fence_reference.lease_sha256 == renewed.semantic_sha256
    assert value.source_lease.semantic_sha256 == source_lease
    assert value.source_lease.fence == renewed.fence
    current = h.store.restore(h.scope)
    h.publish(h.next(current, command="later"))
    with _repeatable_read_transaction(h.engine) as connection:
        h.store.recheck_reference_in_transaction(connection, value)
    assert value.receipt == second
    h.store = h.new_store()
    restarted = h.store.resolve_reference(capture(h, "next", source_lease_sha256=source_lease))
    assert restarted.receipt == second and restarted.previous_receipt == previous.receipt


def test_shared_journal_pool_interns_original_reference_rows_before_ownership(h):
    previous = h.store.restore(h.scope)
    h.publish(h.next(previous))
    pool = DetachedJournalCapture(max_bytes=32 * 1024 * 1024, max_metadata_bytes=2 * 1024 * 1024)
    first = capture(h, journal_pool=pool)
    second = capture(h, "next", journal_pool=pool)
    assert first.journal.head_anchor is second.journal.head_anchor
    assert (
        first.journal.requested_receipt.append is second.previous_journal.requested_receipt.append
    )
    assert first.lease == second.previous_lease
    h.store.require_reference(h.store.resolve_reference(second))


@pytest.mark.parametrize(
    "kind", ["raw_copy", "raw_fields", "resolved_copy", "foreign", "nested_read"]
)
def test_reference_owned_identity_and_original_detached_content_are_required(h, kind):
    raw = capture(h)
    if kind == "raw_copy":
        with pytest.raises(ContinuousAccountConflict):
            h.store.resolve_reference(replace(raw))
        return
    if kind == "raw_fields":
        object.__setattr__(raw, "current", replace(raw.current))
        with pytest.raises(ContinuousAccountConflict):
            h.store.resolve_reference(raw)
        return
    value = h.store.resolve_reference(raw)
    if kind == "resolved_copy":
        value = replace(value)
    elif kind == "foreign":
        h.store = h.new_store()
    else:
        object.__setattr__(value.journal, "head", replace(value.journal.head, sequence=0))
    with pytest.raises(ContinuousAccountConflict):
        h.store.require_reference(value)


@pytest.mark.parametrize("target", ["index", "journal", "lease"])
def test_changed_original_reference_rows_fail_final_readback(h, target):
    value = h.store.resolve_reference(capture(h))
    with h.engine.begin() as connection:
        if target == "index":
            connection.execute(
                sa.update(continuous_account_commits).values(receipt_sha256="f" * 64)
            )
        elif target == "journal":
            connection.execute(sa.update(journal_entries).values(payload=b"{}"))
        else:
            connection.execute(sa.update(phase2_account_leases).values(owner_id="changed-owner"))
    with _repeatable_read_transaction(h.engine) as connection, pytest.raises(ValueError):
        h.store.recheck_reference_in_transaction(connection, value)
    with pytest.raises(ValueError):
        h.store.resolve_reference(capture(h))


def test_missing_reference_is_absent_without_a_producer_claim(h):
    assert capture(h, "missing") is None
