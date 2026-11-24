"""Cooperative stop is an extra local denial at the actual account SQL boundary."""

from concurrent.futures import ThreadPoolExecutor
from copy import copy
from dataclasses import replace
from gc import collect
from threading import Event
from weakref import ref

import pytest
import sqlalchemy as sa

from packages.persistence.continuous_account import ContinuousAccountConflict
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_admissions,
    daily_runtime_hold_heads,
)
from tests.integration import test_continuous_account_store as account_fixture
from tests.integration import test_continuous_composition as composition_fixture

h = account_fixture.h
case = composition_fixture.case


def test_absent_stop_scope_preserves_original_commit_restore_and_retry(h):
    first = h.publish(h.prepare())
    previous = h.store.restore(h.scope)
    assert previous.receipt == first
    second = h.publish(h.next(previous))
    restored = h.store.restore(h.scope)
    assert restored.receipt == second
    with h.store.write_transaction() as connection:
        assert (
            h.store.retry_in_transaction(
                connection,
                original=restored,
                command_sha256=second.commit.transition.command_sha256,
                fence=h.fence,
            )
            == second
        )
    assert not h.store._cooperative_writes


def test_exact_event_required_without_calling_user_predicates(h):
    class EventSubclass(Event):
        pass

    def forbidden():
        pytest.fail("caller predicate must not run")

    for invalid in (False, True, object(), forbidden, EventSubclass()):
        with pytest.raises(ContinuousAccountConflict, match="EXACT_CONTINUOUS_STOP_EVENT"):
            h.store.cooperative_stop_scope(invalid)
    event = Event()
    event.is_set = forbidden
    with h.store.cooperative_stop_scope(event):
        receipt = h.publish(h.prepare())
    assert h.store.restore(h.scope).receipt == receipt


def test_stop_at_scope_entry_latches_despite_clear_and_new_event(h):
    event = Event()
    scope = h.store.cooperative_stop_scope(event)
    event.set()
    with pytest.raises(ContinuousAccountConflict, match="COOPERATIVE_STOPPED"), scope:
        pytest.fail("stopped scope entered")
    event.clear()
    with pytest.raises(ContinuousAccountConflict, match="COOPERATIVE_STOPPED"):
        h.store.cooperative_stop_scope(Event())
    with (
        pytest.raises(ContinuousAccountConflict, match="COOPERATIVE_STOPPED"),
        h.store.write_transaction(),
    ):
        pytest.fail("latched stop reopened without a scope")


@pytest.mark.parametrize("mutation", ["copy", "replace", "event", "account"])
def test_scope_requires_exact_original_instance_and_original_fields(h, mutation):
    scope = h.store.cooperative_stop_scope(Event())
    candidate = scope
    if mutation == "copy":
        candidate = copy(scope)
    elif mutation == "replace":
        candidate = replace(scope)
    elif mutation == "event":
        object.__setattr__(candidate, "stop_event", Event())
    else:
        object.__setattr__(candidate, "account", h.new_store())
    with (
        pytest.raises(ContinuousAccountConflict, match="ORIGINAL_CONTINUOUS_STOP_SCOPE"),
        candidate,
    ):
        pytest.fail("copied or mutated scope entered")


def test_scope_is_one_use_and_rejects_nested_conflicting_scopes(h):
    event = Event()
    scope = h.store.cooperative_stop_scope(event)
    other = h.store.cooperative_stop_scope(Event())
    same_event = h.store.cooperative_stop_scope(event)
    with scope:
        for nested in (scope, other, same_event):
            with (
                pytest.raises(ContinuousAccountConflict, match="STOP_SCOPE_CONFLICT"),
                nested,
            ):
                pytest.fail("nested scope entered")
        h.publish(h.prepare())
    with pytest.raises(ContinuousAccountConflict, match="STOP_SCOPE_CONFLICT"), scope:
        pytest.fail("used scope entered again")
    with other:
        h.publish(h.next(h.store.restore(h.scope)))


def test_event_cannot_change_class_after_original_scope_was_issued(h):
    class EventSubclass(Event):
        def __getattribute__(self, name):
            pytest.fail("changed Event class must not receive attribute callbacks")

    event = Event()
    scope = h.store.cooperative_stop_scope(event)
    event.__class__ = EventSubclass
    with (
        pytest.raises(ContinuousAccountConflict, match="ORIGINAL_CONTINUOUS_STOP_SCOPE"),
        scope,
    ):
        pytest.fail("changed Event class entered")


def test_finished_scopes_are_not_retained_by_original_ownership_registry(h):
    scope = h.store.cooperative_stop_scope(Event())
    weak = ref(scope)
    with scope:
        pass
    del scope
    collect()
    assert weak() is None
    assert not h.store._cooperative_stop_owned
    assert not h.store._cooperative_stop_fields
    assert not h.store._cooperative_stop_used


def test_scope_enter_exit_and_write_are_bound_to_original_thread(h):
    scope = h.store.cooperative_stop_scope(Event())

    def foreign_write():
        with h.store.write_transaction():
            pytest.fail("foreign thread entered account SQL")

    with ThreadPoolExecutor(max_workers=1) as executor:
        with pytest.raises(ContinuousAccountConflict, match="STOP_SCOPE_THREAD_CHANGED"):
            executor.submit(scope.__enter__).result(timeout=5)
        with scope:
            for operation in (foreign_write, lambda: scope.__exit__(None, None, None)):
                with pytest.raises(ContinuousAccountConflict, match="STOP_SCOPE_THREAD_CHANGED"):
                    executor.submit(operation).result(timeout=5)
            h.publish(h.prepare())
    assert not h.store._cooperative_writes
    assert h.store._cooperative_stop_scope is None


def test_wrong_thread_cannot_finish_original_scoped_transaction(h):
    prepared = h.prepare()
    with h.store.cooperative_stop_scope(Event()), ThreadPoolExecutor(max_workers=1) as executor:
        transaction = h.store.write_transaction()
        connection = transaction.__enter__()
        h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)
        with pytest.raises(ContinuousAccountConflict, match="STOP_SCOPE_THREAD_CHANGED"):
            executor.submit(transaction.__exit__, None, None, None).result(timeout=5)
    with h.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(continuous_account_commits))
            == 0
        )
    assert not h.store._pending_publications
    assert not h.store._write_connections
    assert not h.store._cooperative_writes


def test_other_thread_can_signal_stop_and_write_entry_observes_it(h):
    prepared = h.prepare()
    event = Event()
    with h.store.cooperative_stop_scope(event), ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(event.set).result(timeout=5)
        with pytest.raises(ContinuousAccountConflict, match="COOPERATIVE_STOPPED"):
            h.publish(prepared)
        event.clear()
        with pytest.raises(ContinuousAccountConflict, match="COOPERATIVE_STOPPED"):
            h.publish(prepared)
    with h.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(continuous_account_commits))
            == 0
        )


def test_scope_cannot_be_introduced_during_an_existing_unscoped_write(h):
    prepared = h.prepare()
    scope = h.store.cooperative_stop_scope(Event())
    with h.store.write_transaction() as connection:
        with pytest.raises(ContinuousAccountConflict, match="STOP_SCOPE_CONFLICT"), scope:
            pytest.fail("scope changed during existing write")
        receipt = h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)
    assert h.store.restore(h.scope).receipt == receipt


def test_scope_exit_during_original_write_latches_and_forces_rollback(h):
    prepared = h.prepare()
    scope = h.store.cooperative_stop_scope(Event())
    scope.__enter__()
    with (
        pytest.raises(ContinuousAccountConflict, match="STOP_SCOPE_CHANGED"),
        h.store.write_transaction() as connection,
    ):
        h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)
        with pytest.raises(ContinuousAccountConflict, match="STOP_SCOPE_WRITE_ACTIVE"):
            scope.__exit__(None, None, None)
    with h.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(continuous_account_commits))
            == 0
        )
    assert not h.store._cooperative_writes
    with (
        pytest.raises(ContinuousAccountConflict, match="COOPERATIVE_STOPPED"),
        h.store.write_transaction(),
    ):
        pytest.fail("scope misuse reopened stopped account")


def test_scope_exit_latches_stop_without_masking_original_failure(h):
    event = Event()
    with (
        pytest.raises(RuntimeError, match="original operation failed"),
        h.store.cooperative_stop_scope(event),
    ):
        event.set()
        raise RuntimeError("original operation failed")
    event.clear()
    with pytest.raises(ContinuousAccountConflict, match="COOPERATIVE_STOPPED"):
        h.store.cooperative_stop_scope(event)


@pytest.mark.parametrize("signal_at", ["body", "readback", "fence"])
def test_observed_stop_rolls_back_actual_financial_holds_admission_and_checkpoint(
    case, monkeypatch, signal_at
):
    case.publish()
    previous, transition, ref, admissions = case.next()
    prepared = case.store.prepare(
        transition, scope=case.scope, previous=previous, source_evidence=ref, admissions=admissions
    )
    before = case.h.counts()
    event = Event()
    completed_checks = []
    original_readback = case.store._recheck_publication
    original_fence = case.store._revalidate_publication_fence

    def readback(*args, **kwargs):
        result = original_readback(*args, **kwargs)
        completed_checks.append("readback")
        if signal_at == "readback":
            event.set()
        return result

    def fence(*args, **kwargs):
        result = original_fence(*args, **kwargs)
        completed_checks.append("fence")
        if signal_at == "fence":
            event.set()
        return result

    def forbidden_commit():
        pytest.fail("actual COMMIT reached after observed stop")

    with (
        case.store.cooperative_stop_scope(event),
        pytest.raises(ContinuousAccountConflict, match="COOPERATIVE_STOPPED"),
        case.store.write_transaction() as connection,
    ):
        case.store.commit_in_transaction(connection, prepared=prepared, fence=case.h.lease.fence)
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_admissions)) == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_hold_heads)) > 0
        )
        monkeypatch.setattr(connection, "commit", forbidden_commit)
        monkeypatch.setattr(case.store, "_recheck_publication", readback)
        monkeypatch.setattr(case.store, "_revalidate_publication_fence", fence)
        if signal_at == "body":
            event.set()
    assert completed_checks == ([] if signal_at == "body" else ["readback", "fence"])
    assert case.h.counts() == before
    assert not case.store._pending_publications
    assert not case.store._write_connections
    assert not case.store._cooperative_writes
    with case.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(continuous_account_commits))
            == 1
        )
    assert case.new_store().restore(case.scope).receipt == previous.receipt
