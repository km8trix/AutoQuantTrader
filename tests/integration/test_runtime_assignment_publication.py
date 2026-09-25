"""Real signed owner request and original C/B/A owners at outer assignment COMMIT."""

from contextlib import contextmanager
from dataclasses import replace

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignments
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.runtime_assignment_publication import SqlRuntimeAssignmentPublication
from tests.integration.test_continuous_reconciliation_publication import PublicationCase
from tests.integration.test_continuous_runtime_sources import install_producers
from tests.integration.test_runtime_owner_dependencies import (
    assignment_preparation,
    attach,
)


@pytest.fixture
def selection(tmp_path):
    pair = PublicationCase(tmp_path)
    install_producers(pair.base, pair.model)
    dependencies = attach(pair)
    try:
        yield (pair, *dependencies)
    finally:
        pair.close()


def publisher(selection):
    pair = selection[0]
    return SqlRuntimeAssignmentPublication(account=pair.account, daily=pair.base.h.store)


def test_signed_assignment_changes_only_future_selection_at_same_account_boundary(selection):
    pair = selection[0]
    dep, command, receipt, plan, prepared = assignment_preparation(selection)
    before = pair.account.restore(pair.base.scope)
    result = publisher(selection).publish(prepared, fence=pair.base.h.lease.fence)
    assert result == dep.record.proposed
    assert not result.enabled_for_new_exposure and not result.live_authorized
    assert pair.account.restore(pair.base.scope).receipt == before.receipt
    current = pair.base.h.resolved()
    assert current.assignment == result
    assert current.obligations == prepared.snapshot.obligations
    assert current.control == prepared.snapshot.control
    assert plan.request.read.receipt == receipt
    assert command.after_assignment_sha256 == result.semantic_sha256


@pytest.mark.parametrize("failure", ["assignment", "canonical", "request", "deadline"])
def test_failure_after_install_rolls_back_and_does_not_acknowledge_cutover(
    selection, monkeypatch, failure
):
    pair = selection[0]
    dep, _command, receipt, _plan, prepared = assignment_preparation(selection)
    h = pair.base.h
    original = h.store.install_prepared_in_transaction

    def late(connection, value, *, fence):
        result = original(connection, value, fence=fence)
        if failure == "deadline":
            h.clock.instant = prepared.valid_until
        else:
            if failure == "assignment":
                statement = (
                    sa.update(daily_runtime_assignments)
                    .where(daily_runtime_assignments.c.generation == result.generation)
                    .values(payload=b"changed")
                )
            elif failure == "canonical":
                statement = (
                    sa.update(continuous_account_commits)
                    .where(
                        continuous_account_commits.c.command_id
                        == dep.previous.receipt.commit.transition.command_id
                    )
                    .values(checkpoint_sha256="f" * 64)
                )
            else:
                statement = (
                    sa.update(journal_entries)
                    .where(journal_entries.c.key_sha256 == receipt.previous_head.key_sha256)
                    .values(payload=b"changed")
                )
            assert connection.execute(statement).rowcount == 1
        return result

    monkeypatch.setattr(h.store, "install_prepared_in_transaction", late)
    with pytest.raises(ValueError):
        publisher(selection).publish(prepared, fence=h.lease.fence)
    with pair.base.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.max(daily_runtime_assignments.c.generation)))
            == prepared.snapshot.assignment.generation
        )


def test_copied_assignment_preparation_is_not_publication_authority(selection):
    _dep, _command, _receipt, _plan, prepared = assignment_preparation(selection)
    with pytest.raises(ValueError):
        publisher(selection).publish(replace(prepared), fence=selection[0].base.h.lease.fence)


def test_assignment_outer_write_and_final_readbacks_do_not_decode_or_read_objects(
    selection, monkeypatch
):
    pair = selection[0]
    _dep, _command, _receipt, _plan, prepared = assignment_preparation(selection)
    original = pair.account.write_transaction

    def forbidden(*args, **kwargs):
        raise AssertionError("heavy work under assignment SQL")

    @contextmanager
    def guarded():
        with original() as connection, monkeypatch.context() as patch:
            patch.setattr(codec, "encode_record", forbidden)
            patch.setattr(codec, "decode_record", forbidden)
            patch.setattr(pair.base.artifacts, "read", forbidden)
            patch.setattr(pair.base.artifacts, "put", forbidden)
            yield connection

    monkeypatch.setattr(pair.account, "write_transaction", guarded)
    publisher(selection).publish(prepared, fence=pair.base.h.lease.fence)
