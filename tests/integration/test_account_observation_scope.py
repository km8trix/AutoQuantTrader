"""Exact owned committed clock observations; these views confer no risk authority."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa

from packages.domain.account_coordinator import AccountCoordinatorError
from packages.persistence import account_coordinator as persistence
from packages.persistence.account_coordinator import SqlAccountCoordinator
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.schema import phase2_account_lease_heads as heads
from tests.integration.test_sql_account_coordinator import (
    coordinator,
    sqlite_engine,  # noqa: F401
)


def head(engine):
    with engine.connect() as connection:
        return dict(connection.execute(sa.select(heads)).mappings().one())


def recheck(owner, engine, view):
    with _repeatable_read_transaction(engine) as connection:
        return owner.recheck_committed_observations_in_transaction(connection, view)


def test_actual_advancing_utc_observations_keep_exact_original_fields_and_close(
    sqlite_engine,  # noqa: F811
):
    class ActualUtcClock:
        def now(self):
            return datetime.now(UTC)

    owner, _clock, _authority = coordinator(sqlite_engine, "scope", clock=ActualUtcClock())
    lease = owner.acquire("owner")
    original = head(sqlite_engine)
    with owner.inspect_committed_observations(lease.fence, original_head=original) as view:
        assert view.original_head == original
        previous = original
        for _ in range(3):
            checked = owner.revalidate(lease.fence)
            actual = head(sqlite_engine)
            assert actual["updated_at"] > previous["updated_at"]
            assert actual["updated_at"].replace(tzinfo=UTC) >= checked.validated_at
            assert {k: v for k, v in actual.items() if k != "updated_at"} == {
                k: v for k, v in original.items() if k != "updated_at"
            }
            assert recheck(owner, sqlite_engine, view) == actual
            previous = actual
        assert not hasattr(view, "permit") and not hasattr(view, "fence")
    with pytest.raises(AccountCoordinatorError, match="original active"):
        recheck(owner, sqlite_engine, view)
    assert owner._state.observations is None


def test_scope_rejects_changed_input_and_unowned_timestamp_before_overwrite(
    sqlite_engine,  # noqa: F811
):
    owner, clock, _authority = coordinator(sqlite_engine, "scope")
    lease = owner.acquire("owner")
    original = head(sqlite_engine)
    with (
        pytest.raises(AccountCoordinatorError, match=r"original observed.*changed"),
        owner.inspect_committed_observations(
            lease.fence,
            original_head=original
            | {"updated_at": original["updated_at"] + timedelta(microseconds=1)},
        ),
    ):
        pass
    with owner.inspect_committed_observations(lease.fence, original_head=original) as view:
        changed = original["updated_at"] + timedelta(microseconds=1)
        with sqlite_engine.begin() as connection:
            connection.execute(sa.update(heads).values(updated_at=changed))
        clock.advance(timedelta(seconds=1))
        with pytest.raises(AccountCoordinatorError, match="unowned committed"):
            owner.revalidate(lease.fence)
        assert head(sqlite_engine)["updated_at"] == changed
        with pytest.raises(AccountCoordinatorError, match="original active"):
            recheck(owner, sqlite_engine, view)
    assert owner._state.observations is None


def test_scope_rejects_unowned_other_head_fields_at_final_readback(
    sqlite_engine,  # noqa: F811
):
    owner, _clock, _authority = coordinator(sqlite_engine, "scope")
    lease = owner.acquire("owner")
    original = head(sqlite_engine)
    with owner.inspect_committed_observations(lease.fence, original_head=original) as view:
        with sqlite_engine.begin() as connection:
            connection.execute(
                sa.update(heads).values(current_fencing_generation=None, current_lease_sha256=None)
            )
        with pytest.raises(AccountCoordinatorError, match="unowned committed"):
            recheck(owner, sqlite_engine, view)


def test_foreign_coordinator_thread_and_copied_view_cannot_advance_scope(
    sqlite_engine,  # noqa: F811
):
    owner, clock, authority = coordinator(sqlite_engine, "scope")
    lease = owner.acquire("owner")
    foreign = SqlAccountCoordinator(account_id="scope", authority=authority)
    original = head(sqlite_engine)
    with owner.inspect_committed_observations(lease.fence, original_head=original) as view:
        clock.advance(timedelta(seconds=1))
        with pytest.raises(AccountCoordinatorError, match="original active"):
            foreign.revalidate(lease.fence)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(owner.revalidate, lease.fence)
            with pytest.raises(AccountCoordinatorError, match="original active"):
                future.result(timeout=5)
        for invalid_owner, invalid_view in ((foreign, view), (owner, replace(view))):
            with pytest.raises(AccountCoordinatorError, match="original active"):
                recheck(invalid_owner, sqlite_engine, invalid_view)
        assert head(sqlite_engine) == original
        assert recheck(owner, sqlite_engine, view) == original
        owner.revalidate(lease.fence)
        assert recheck(owner, sqlite_engine, view) == head(sqlite_engine)


@pytest.mark.parametrize("failure", ["rollback", "ambiguous_commit"])
def test_failed_or_ambiguous_commit_never_advances_or_qualifies_scope(
    sqlite_engine,  # noqa: F811
    monkeypatch,
    failure,
):
    owner, clock, _authority = coordinator(sqlite_engine, "scope")
    lease = owner.acquire("owner")
    original = head(sqlite_engine)
    actual_write = persistence._write_transaction

    @contextmanager
    def fail_write(engine):
        with actual_write(engine) as connection:
            yield connection
            if failure == "rollback":
                raise RuntimeError("fixture precommit failure")
        raise RuntimeError("fixture ambiguous commit result")

    with owner.inspect_committed_observations(lease.fence, original_head=original) as view:
        clock.advance(timedelta(seconds=1))
        with monkeypatch.context() as patch:
            patch.setattr(persistence, "_write_transaction", fail_write)
            with pytest.raises(RuntimeError, match="fixture"):
                owner.revalidate(lease.fence)
        assert owner._state.observations.expected == original
        assert owner._state.observations.count == 0
        assert (head(sqlite_engine) == original) is (failure == "rollback")
        with pytest.raises(AccountCoordinatorError, match="original active"):
            recheck(owner, sqlite_engine, view)
    assert owner._state.observations is None


def test_rollback_guards_do_not_advance_and_observation_count_is_bounded(
    sqlite_engine,  # noqa: F811
    monkeypatch,
):
    owner, clock, _authority = coordinator(sqlite_engine, "scope")
    lease = owner.acquire("owner")
    original = head(sqlite_engine)
    monkeypatch.setattr(persistence, "MAX_COMMITTED_ACCOUNT_OBSERVATIONS", 2)
    with owner.inspect_committed_observations(lease.fence, original_head=original) as view:
        clock.advance(timedelta(seconds=1))
        with _repeatable_read_transaction(sqlite_engine) as connection:
            owner.revalidate_for_commit_in_transaction(connection, lease.fence)
        assert head(sqlite_engine) == original
        assert recheck(owner, sqlite_engine, view) == original
        assert owner._state.observations.count == 0
        for _ in range(2):
            owner.revalidate(lease.fence)
        before = head(sqlite_engine)
        with pytest.raises(AccountCoordinatorError, match="scope bound"):
            owner.revalidate(lease.fence)
        assert head(sqlite_engine) == before
    assert owner._state.observations is None
    owner.revalidate(lease.fence)
