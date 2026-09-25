"""Actual C/journal captures are compared without replay or source I/O."""

from dataclasses import replace

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.domain.continuous_persistence_contracts import (
    CONTINUOUS_COMMIT_SCHEMA,
    ContinuousAccountCommit,
)
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.detached_journal_capture import DetachedJournalCapture
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.schema import phase2_account_leases
from tests.integration.test_continuous_publication_reference import capture, forbidden
from tests.integration.test_continuous_publication_reference import h as h


def test_actual_complete_reference_and_journal_inputs_without_sql_codec_or_restore(h, monkeypatch):
    previous = h.store.restore(h.scope)
    h.publish(h.next(previous))
    pool = DetachedJournalCapture(max_bytes=32 * 1024 * 1024, max_metadata_bytes=2 * 1024 * 1024)
    old = capture(h, "next", journal_pool=pool)
    fresh = capture(h, "next")
    assert old is not fresh and old.previous is not None and fresh.previous is not None
    journal = h.store.journal
    old_read = journal.resolve_snapshot(old.journal)
    fresh_read = journal.resolve_snapshot(fresh.journal)
    reached = []

    def forbid_sql(*_args, **_kwargs):
        pytest.fail("comparison entered SQL")

    sa.event.listen(h.engine, "before_cursor_execute", forbid_sql)
    try:
        with monkeypatch.context() as guarded:
            for owner, names in (
                (codec, ("encode_record", "decode_record")),
                (h.artifacts, ("read",)),
                (h.store, ("restore", "resolve_reference", "require_reference")),
                (journal, ("resolve_snapshot", "capture_in_transaction", "recheck_in_transaction")),
            ):
                for name in names:
                    guarded.setattr(owner, name, forbidden)
            assert (
                h.store.require_same_reference_capture(
                    old, fresh, comparison=ContinuousCaptureComparison()
                )
                is None
            )
            assert (
                journal.require_same_resolved_read(
                    old_read, fresh_read, comparison=ContinuousCaptureComparison()
                )
                is None
            )
            # Raw journal captures intentionally accept legitimate pool copies;
            # the enclosing C capture still requires its original registry object.
            assert (
                journal.require_same_capture(
                    old.journal, replace(fresh.journal), comparison=ContinuousCaptureComparison()
                )
                is None
            )
            with pytest.raises(ValueError):
                h.store.require_same_reference_capture(
                    old, replace(fresh), comparison=ContinuousCaptureComparison()
                )
            reached.append("actual original reference and journal comparisons")
    finally:
        sa.event.remove(h.engine, "before_cursor_execute", forbid_sql)
    assert reached == ["actual original reference and journal comparisons"]
    h.store.require_reference(h.store.resolve_reference(old))


def test_actual_capture_comparison_rejects_private_rows_then_accepts_rolled_back_original(h):
    original = capture(h)
    statements = (
        sa.update(continuous_account_commits).values(receipt_sha256="f" * 64),
        sa.update(journal_entries).values(payload=b"{}"),
        sa.update(phase2_account_leases).values(owner_id="changed-owner"),
    )
    reached = []
    for index, statement in enumerate(statements):
        with _repeatable_read_transaction(h.engine) as connection:
            assert connection.execute(statement).rowcount == 1
            changed = h.store.capture_reference_in_transaction(
                connection, scope=h.scope, command_id="initialize"
            )
            assert changed is not None
            connection.rollback()
        with pytest.raises(ValueError):
            h.store.require_same_reference_capture(
                original, changed, comparison=ContinuousCaptureComparison()
            )
        h.store.require_same_reference_capture(
            original, capture(h), comparison=ContinuousCaptureComparison()
        )
        reached.append(index)
    assert reached == [0, 1, 2]


def test_complete_historical_journal_comparison_keeps_new_current_head_and_owner_denial(h):
    original = capture(h)
    previous = h.store.restore(h.scope)
    h.publish(h.next(previous))
    later = capture(h)
    assert original.journal.requested_receipt == later.journal.requested_receipt
    assert original.journal.stream != later.journal.stream
    with pytest.raises(ValueError):
        h.store.require_same_reference_capture(
            original, later, comparison=ContinuousCaptureComparison()
        )
    foreign = SqlDurableJournal(
        h.engine, codec=codec, record_types={CONTINUOUS_COMMIT_SCHEMA: ContinuousAccountCommit}
    )
    assert foreign is not h.store.journal
    assert foreign._preparation_owner is not h.store.journal._preparation_owner
    with pytest.raises(ValueError):
        foreign.require_same_capture(
            original.journal, original.journal, comparison=ContinuousCaptureComparison()
        )
    with pytest.raises(ValueError):
        h.store.journal.require_same_capture(original.journal, later.journal, comparison=object())
