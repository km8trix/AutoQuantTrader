"""Actual original C/B/A/attempt source owners; modeled data, no venue send."""

from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_attempt_publication import (
    CommittedSimulationAttemptBatch,
    SqlContinuousAttemptPublication,
)
from packages.persistence.daily_runtime_risk_schema import daily_runtime_attempt_heads
from tests.integration import test_continuous_runtime_attempt_sources as source_fixture

attempt_case = source_fixture.attempt_case


def preparation(attempt_case):
    case, service, reader, previous, _current, admission = attempt_case
    if service.attempt_sources is None:
        service.bind_attempt_sources(reader)
    case.h.clock.instant += timedelta(milliseconds=1)
    current = case.h.resolved()
    source = reader.retain_pending(
        coordinator_command_id="actual-pending-parent",
        previous=previous,
        current=current,
        admissions=(admission,),
    )
    raw = case.h.store.read_attempt_snapshot(
        account_id=case.scope.account_id,
        fence=case.h.lease.fence,
        envelopes=source.envelopes,
        preparations=source.closure.preparations,
    )
    resolved = case.h.store.resolve_snapshot(raw)
    mutation = case.h.store.prepare_attempt_mutation(resolved)
    transition = case.owner.prepare_runtime_action(
        command_id=source.source.coordinator_command_id,
        checkpoint=previous.checkpoint,
        action=source.action,
    )
    account = case.store.prepare(
        transition,
        scope=case.scope,
        previous=previous,
        source_evidence=source.reference,
        attempts=mutation,
    )
    return source, mutation, account


def test_pending_atomic_publication_restores_original_hold_capacity_and_inert_retry(attempt_case):
    case, _service, _reader, previous, _current, _admission = attempt_case
    source, mutation, prepared = preparation(attempt_case)
    publication = SqlContinuousAttemptPublication(account=case.store)
    with pytest.raises(ValueError, match="FIRST_SEND"):
        publication.publish_dispatch(prepared, fence=case.h.lease.fence)
    receipt = publication.publish(prepared, fence=case.h.lease.fence)
    with pytest.raises(ValueError, match="SUCCESSFUL_DISPATCH_COMMIT"):
        publication.require_completed(CommittedSimulationAttemptBatch(receipt, prepared, mutation))
    current = case.h.resolved()
    restored = case.store.restore(case.scope)
    assert restored.receipt == receipt
    assert restored.checkpoint.state == previous.checkpoint.state
    assert restored.checkpoint.current == previous.checkpoint.current
    assert restored.checkpoint.now == source.source.checked_at > previous.checkpoint.now
    assert restored.checkpoint.runtime_decisions == previous.checkpoint.runtime_decisions
    assert current.attempts == mutation.result.attempts
    assert all(item.state.value == "pending" for item in current.attempts)
    assert current.obligations == mutation.result.obligations == mutation.snapshot.obligations
    assert (
        restored.receipt.commit.transition.resulting_heads.attempt_sha256
        != previous.receipt.commit.transition.resulting_heads.attempt_sha256
    )
    with case.store.write_transaction() as connection:
        retried = case.store.retry_in_transaction(
            connection,
            original=restored,
            command_sha256=prepared.commit.transition.command_sha256,
            fence=case.h.lease.fence,
        )
    assert retried is restored.receipt
    assert case.h.resolved().attempts == current.attempts


@pytest.mark.parametrize("fault", ["attempt", "canonical", "deadline"])
def test_mutation_after_c_publication_cannot_escape_outer_rollback(
    attempt_case, monkeypatch, fault
):
    case, _service, _reader, previous, _current, _admission = attempt_case
    _source, _mutation, prepared = preparation(attempt_case)
    original = case.store.commit_in_transaction

    def late(connection, *, prepared, fence):
        receipt = original(connection, prepared=prepared, fence=fence)
        if fault == "deadline":
            case.h.clock.instant = prepared.composition.valid_until
        elif fault == "attempt":
            assert (
                connection.execute(
                    sa.update(daily_runtime_attempt_heads).values(attempt_sha256="f" * 64)
                ).rowcount
                > 0
            )
        else:
            assert (
                connection.execute(
                    sa.update(continuous_account_commits)
                    .where(
                        continuous_account_commits.c.command_id
                        == prepared.commit.transition.command_id
                    )
                    .values(checkpoint_sha256="f" * 64)
                ).rowcount
                == 1
            )
        return receipt

    monkeypatch.setattr(case.store, "commit_in_transaction", late)
    with pytest.raises(ValueError):
        SqlContinuousAttemptPublication(account=case.store).publish(
            prepared, fence=case.h.lease.fence
        )
    with case.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_attempt_heads))
            == 0
        )
        assert (
            connection.scalar(sa.select(sa.func.max(continuous_account_commits.c.sequence)))
            == previous.receipt.commit.sequence
        )


def test_attempt_publication_uses_only_prepared_values_and_bounded_sql(attempt_case, monkeypatch):
    case = attempt_case[0]
    _source, mutation, prepared = preparation(attempt_case)
    with pytest.raises(ValueError):
        case.h.store.require_prepared_attempt(replace(mutation))
    original = case.store.write_transaction

    def forbidden(*args, **kwargs):
        raise AssertionError("heavy work under attempt publication SQL")

    @contextmanager
    def guarded():
        with original() as connection, monkeypatch.context() as patch:
            patch.setattr(codec, "encode_record", forbidden)
            patch.setattr(codec, "decode_record", forbidden)
            patch.setattr(case.artifacts, "read", forbidden)
            patch.setattr(case.artifacts, "put", forbidden)
            yield connection

    monkeypatch.setattr(case.store, "write_transaction", guarded)
    SqlContinuousAttemptPublication(account=case.store).publish(prepared, fence=case.h.lease.fence)
