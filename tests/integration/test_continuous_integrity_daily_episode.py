"""Original signed-genesis B reuse; synthetic sources/time, no provider authority."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import copy
from datetime import timedelta
from decimal import Decimal
from itertools import pairwise

import pytest
import sqlalchemy as sa

from packages.persistence.continuous_integrity import ContinuousIntegrityError, _OriginalObjects
from packages.persistence.daily_runtime_risk import ResolvedDailyRuntimeSnapshot
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignments
from packages.persistence.schema import phase2_account_lease_heads
from tests.integration import test_continuous_integrity as original_fixture
from tests.integration import test_continuous_observed_financial_publication as observed_fixture
from tests.integration.test_continuous_runtime_attempt_sources import attempt_case as attempt_case

case = original_fixture.case
observed_graph = observed_fixture.graph
reader_for = original_fixture.reader_for


def _validate(reader):
    reader.validate_snapshot(reader._capture())


def test_original_complete_daily_is_reused_but_both_index_guards_run(case, monkeypatch):
    reader = reader_for(case)
    reads, indexes, borrowed = [], [], []
    read = reader.daily.read_snapshot
    resolve_index = reader.account.resolve_index
    borrow = reader._borrow_original_daily

    def actual_read(**kwargs):
        result = read(**kwargs)
        reads.append(result)
        return result

    def actual_index(*args, **kwargs):
        result = resolve_index(*args, **kwargs)
        indexes.append(result)
        return result

    def actual_borrow(episode, *, consumer):
        result = borrow(episode, consumer=consumer)
        borrowed.append((episode, result, result.raw.receipt))
        return result

    monkeypatch.setattr(reader.daily, "read_snapshot", actual_read)
    monkeypatch.setattr(reader.account, "resolve_index", actual_index)
    monkeypatch.setattr(reader, "_borrow_original_daily", actual_borrow)
    before = case[0].counts()
    _validate(reader)
    assert len(reads) == 1
    # Genesis discovery plus the per-row outer and inner resolve_index guards.
    assert len(indexes) == len(borrowed) == 3
    assert all(value is borrowed[0][1] for _, value, _ in borrowed)
    assert all(receipt is reads[0].receipt for _, _, receipt in borrowed)
    assert reader._daily_episode is None and reader.composer._integrity_daily is None
    assert case[0].counts() == before
    with pytest.raises(ContinuousIntegrityError, match="EPISODE_REQUIRED"):
        borrow(borrowed[0][0], consumer=reader.composer)
    # Ordinary use outside the integrity episode remains a fresh complete read.
    reader.composer._historical_current()
    assert len(reads) == 2


@pytest.mark.parametrize(
    "change", ["assignment", "policy", "obligations", "control", "receipt", "usage", "rows"]
)
def test_nested_original_values_cannot_change_while_sql_is_unchanged(case, monkeypatch, change):
    reader = reader_for(case)
    borrow = reader._borrow_original_daily
    restore = []
    calls = 0

    def tamper(episode, *, consumer):
        nonlocal calls
        calls += 1
        if calls == 2:
            current = episode.current
            owner, name, value = {
                "assignment": (current.assignment, "enabled_for_new_exposure", True),
                "policy": (current.assignment.policy, "fee_per_share", Decimal("8")),
                "obligations": (current.obligations, "daily_universe_sha256", "9" * 64),
                "control": (current.control, "command_id", "changed-original-control"),
                "receipt": (
                    current.raw.receipt,
                    "validated_at",
                    current.raw.receipt.validated_at + timedelta(microseconds=1),
                ),
                "usage": (current.raw, "capture_usage", (1, 1, 1)),
                "rows": (current.raw.tables[0], "rows", tuple([*current.raw.tables[0].rows])),
            }[change]
            old = getattr(owner, name)
            if name == "rows" and value is old:
                value = (*old, {})
            restore.append((owner, name, old))
            object.__setattr__(owner, name, value)
        return borrow(episode, consumer=consumer)

    monkeypatch.setattr(reader, "_borrow_original_daily", tamper)
    before = case[0].counts()
    try:
        with pytest.raises(ContinuousIntegrityError):
            _validate(reader)
    finally:
        for owner, name, old in restore:
            object.__setattr__(owner, name, old)
    assert calls == 2 and case[0].counts() == before
    assert reader._daily_episode is None and reader.composer._integrity_daily is None


@pytest.mark.parametrize("change", ["token", "reader", "consumer", "thread", "nested"])
def test_original_episode_rejects_copies_foreign_consumers_threads_and_reentry(
    case, monkeypatch, change
):
    reader = reader_for(case)
    borrow = reader._borrow_original_daily

    def foreign(episode, *, consumer):
        if change == "token":
            return borrow(copy(episode), consumer=consumer)
        if change == "reader":
            return copy(reader)._borrow_original_daily(episode, consumer=consumer)
        if change == "consumer":
            return borrow(episode, consumer=copy(consumer))
        if change == "thread":
            with ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(borrow, episode, consumer=consumer).result(timeout=5)
        with reader._original_daily_episode(
            original=episode.original,
            observations=episode.observations,
            current=episode.current,
            objects=episode.objects,
        ):
            pytest.fail("nested episode was accepted")

    monkeypatch.setattr(reader, "_borrow_original_daily", foreign)
    with pytest.raises(ContinuousIntegrityError):
        _validate(reader)
    assert reader._daily_episode is None and reader.composer._integrity_daily is None


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_base_exception_closes_binding_and_preserves_original_failure(case, monkeypatch, failure):
    reader = reader_for(case)
    borrow = reader._borrow_original_daily
    injected = failure("explicit original fixture failure")

    def interrupt(episode, *, consumer):
        borrow(episode, consumer=consumer)
        raise injected

    monkeypatch.setattr(reader, "_borrow_original_daily", interrupt)
    with pytest.raises((ContinuousIntegrityError, failure)) as caught:
        _validate(reader)
    if failure is not RuntimeError:
        assert caught.value is injected
    assert reader._daily_episode is None and reader.composer._integrity_daily is None
    monkeypatch.setattr(reader, "_borrow_original_daily", borrow)
    _validate(reader)


@pytest.mark.parametrize("change", ["assignment_row", "observation_head", "artifact", "lease"])
def test_original_rows_objects_and_actual_lease_are_rechecked_on_later_borrow(
    case, monkeypatch, change
):
    reader = reader_for(case)
    borrow = reader._borrow_original_daily
    calls = 0
    overwritten = []

    def changed(episode, *, consumer):
        nonlocal calls
        calls += 1
        if calls == 2:
            if change == "assignment_row":
                with reader.engine.begin() as connection:
                    connection.execute(
                        sa.update(daily_runtime_assignments).values(command_sha256="8" * 64)
                    )
            elif change == "observation_head":
                with reader.engine.begin() as connection:
                    connection.execute(
                        sa.update(phase2_account_lease_heads).values(
                            updated_at=episode.current.raw.receipt.validated_at
                            + timedelta(microseconds=1)
                        )
                    )
            elif change == "artifact":
                reference = next(iter(episode.objects.references.values()))
                path = reader.account.artifacts._root / (reference.object_sha256 + ".json")
                overwritten.append((path, path.read_bytes()))
                path.write_bytes(b"{}")
            else:
                case[0].base.h.clock.instant += timedelta(days=1)
        return borrow(episode, consumer=consumer)

    monkeypatch.setattr(reader, "_borrow_original_daily", changed)
    try:
        with pytest.raises(ContinuousIntegrityError):
            _validate(reader)
    finally:
        for path, payload in overwritten:
            path.write_bytes(payload)
    assert calls == 2
    assert reader._daily_episode is None and reader.composer._integrity_daily is None


def test_advancing_clock_never_replaces_original_snapshot_receipt(case, monkeypatch):
    reader = reader_for(case)
    clock = case[0].base.h.clock
    borrowed = []
    borrow = reader._borrow_original_daily

    def advancing(_self):
        clock.instant += timedelta(microseconds=1)
        return clock.instant

    def retain(episode, *, consumer):
        value = borrow(episode, consumer=consumer)
        borrowed.append((value.raw.receipt, clock.instant))
        return value

    monkeypatch.setattr(type(clock), "now", advancing)
    monkeypatch.setattr(reader, "_borrow_original_daily", retain)
    _validate(reader)
    assert len(borrowed) == 3
    assert all(receipt is borrowed[0][0] for receipt, _ in borrowed)
    assert all(receipt.validated_at < at for receipt, at in borrowed)
    assert all(left[1] < right[1] for left, right in pairwise(borrowed))


@pytest.mark.parametrize("replace_composer", [False, True])
@pytest.mark.parametrize("cleanup_throws", [False, True])
def test_primary_failure_survives_replaced_composer_and_cleanup_failure(
    case, monkeypatch, replace_composer, cleanup_throws
):
    reader = reader_for(case)
    composer = reader.composer
    borrow = reader._borrow_original_daily
    original_failure = KeyboardInterrupt("original validation interruption")
    retained = []

    def interrupted(episode, *, consumer):
        borrow(episode, consumer=consumer)
        retained.append(episode)
        if replace_composer:
            reader.composer = object()
        raise original_failure

    def failed_cleanup(*args):
        raise RuntimeError("separate cleanup failure")

    monkeypatch.setattr(reader, "_borrow_original_daily", interrupted)
    if cleanup_throws:
        monkeypatch.setattr(composer, "_unbind_integrity_daily", failed_cleanup)
    with pytest.raises(KeyboardInterrupt) as caught:
        _validate(reader)
    assert caught.value is original_failure
    assert reader._daily_episode is None
    assert composer._integrity_daily is None and composer._integrity_daily_active is None
    reader.composer = composer
    with pytest.raises(ContinuousIntegrityError, match="EPISODE_REQUIRED"):
        borrow(retained[0], consumer=composer)


def test_cleanup_failure_without_primary_denies_and_invalidates_episode(case, monkeypatch):
    reader = reader_for(case)
    cleanup_failure = RuntimeError("cleanup failed after actual final readback")

    def failed_cleanup(*args):
        raise cleanup_failure

    monkeypatch.setattr(reader.composer, "_unbind_integrity_daily", failed_cleanup)
    with pytest.raises(RuntimeError) as caught:
        reader._validate(reader._capture())
    assert caught.value is cleanup_failure
    assert reader._daily_episode is None
    assert reader.composer._integrity_daily is None
    assert reader.composer._integrity_daily_active is None


def test_exact_original_commit_count_bounds_borrows_and_latches_denial(case, monkeypatch):
    reader = reader_for(case)
    borrow = reader._borrow_original_daily
    completed = []

    def exhausted(episode, *, consumer):
        assert episode.maximum_borrows == 3
        for _ in range(episode.maximum_borrows):
            completed.append(borrow(episode, consumer=consumer))
        with pytest.raises(ContinuousIntegrityError, match="CONSUMER_OR_BOUND"):
            borrow(episode, consumer=consumer)
        with pytest.raises(ContinuousIntegrityError, match="EPISODE_REQUIRED"):
            borrow(episode, consumer=consumer)
        return completed[0]

    monkeypatch.setattr(reader, "_borrow_original_daily", exhausted)
    with pytest.raises(ContinuousIntegrityError):
        _validate(reader)
    assert len(completed) == 3 and all(value is completed[0] for value in completed)
    assert reader._daily_episode is None and reader.composer._integrity_daily is None


def test_original_object_pool_charges_one_shared_aggregate_before_excess_read(case, monkeypatch):
    import packages.persistence.continuous_integrity as integrity

    reader = reader_for(case)
    first = reader.account.artifacts.put(b"first explicit budget fixture" * 4)
    second = reader.account.artifacts.put(b"second explicit budget fixture" * 4)
    cap = max(first.byte_count, second.byte_count)
    monkeypatch.setattr(integrity, "MAX_CONTINUOUS_OBJECT_BYTES", cap)
    pool = _OriginalObjects(reader.account)
    pool.inspect(first)
    pool.inspect(first)
    assert pool.total == first.byte_count and len(pool.references) == 1
    read = reader.account.artifacts.read

    def checked(reference, **kwargs):
        assert reference != second, "aggregate admission must precede excess artifact I/O"
        return read(reference, **kwargs)

    monkeypatch.setattr(reader.account.artifacts, "read", checked)
    with pytest.raises(ContinuousIntegrityError, match="OBJECT_CLOSURE_BOUND"):
        pool.inspect(second)


def test_entire_original_snapshot_uses_same_episode_object_pool(case, monkeypatch):
    reader = reader_for(case)
    inspect = _OriginalObjects.inspect
    admitted = []

    def recorded(pool, value):
        before = tuple(pool.references)
        result = inspect(pool, value)
        if type(value) is ResolvedDailyRuntimeSnapshot:
            assert before, "journal objects must already share this original budget"
            admitted.append((pool, value, before, tuple(pool.references)))
        return result

    monkeypatch.setattr(_OriginalObjects, "inspect", recorded)
    _validate(reader)
    assert len(admitted) == 1
    assert set(admitted[0][2]) <= set(admitted[0][3])


@contextmanager
def _owned_source_episode(reader, current):
    """Only the private ownership seam; this does not qualify fixture owner history."""
    original = reader._capture()
    (head,) = original.dependencies[phase2_account_lease_heads.name]
    with reader.account.coordinator.inspect_committed_observations(
        reader.fence, original_head=head
    ) as observations:
        objects = _OriginalObjects(reader.account)
        with reader._original_daily_episode(
            original=original, observations=observations, current=current, objects=objects
        ) as episode:
            yield episode
            reader._require_daily_episode(episode)
            reader.composer._require_integrity_daily(reader, episode)
            objects.recheck()
            reader._recheck_final(original, observations)


def _reader_with_actual_source_owners(pair):
    from apps.api.backtest_views import LocalOperatorSecurity
    from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
    from packages.persistence.runtime_owner_commands import SqlRuntimeOwnerCommands
    from packages.persistence.runtime_owner_dependencies import SqlRuntimeOwnerDependencies

    runtime = pair.base.h.store.producers
    owners = runtime.owner_dependencies
    if owners is None:
        commands = SqlRuntimeOwnerCommands(
            pair.base.engine,
            codec=pair.account.codec,
            authenticator=LocalRuntimeOwnerAuthenticator(
                LocalOperatorSecurity(
                    enabled=False,
                    transport_is_loopback_scoped=False,
                    operator_id="explicit-partial-source-fixture",
                    configured_secret="",
                )
            ),
        )
        owners = SqlRuntimeOwnerDependencies(
            pair.base.engine,
            accounts=pair.account,
            daily=pair.base.h.store,
            publisher=pair.publisher,
            commands=commands,
            artifacts=pair.base.artifacts,
            codec=pair.account.codec,
        )
        runtime.bind_owner_dependencies(owners)
    return reader_for((pair, owners, runtime))


@pytest.mark.parametrize("source_kind", ["attempt", "observed"])
def test_actual_source_owner_and_original_descendant_remain_bound(
    request, monkeypatch, source_kind
):
    # Both fixtures explicitly model initial assignment/control/source/time.
    # No activation, send, authenticated startup or complete integrity claim.
    if source_kind == "attempt":
        from tests.integration.test_continuous_runtime_attempt_sources import (
            publish_original_pending,
        )

        fixture = request.getfixturevalue("attempt_case")
        base, _runtime, owner, *_ = fixture
        publish_original_pending(fixture)
        pair = base.paired_fixture
        current = base.h.resolved()
        source = current.attempt_sources
        assert current.attempts and source is not None
        descendant = source.state.captured.plan.sources[0].closure.previous_checkpoint.object_ref
        owner_field = "runtime_sources"
    else:
        from tests.integration.test_continuous_observed_financial_publication import captured

        pair, wrapper = request.getfixturevalue("observed_graph")
        prepared = wrapper.prepare(**captured(pair))
        current = prepared.holds.snapshot
        source = current.observed_sources
        owner = wrapper.observed
        assert current.raw.requested_observed_source is not None and source is not None
        descendant = source.inputs[0].source.previous_checkpoint.object_ref
        owner_field = "venue_sources"
    reader = _reader_with_actual_source_owners(pair)
    original_guard = owner.require_resolved
    checks = []

    def actual_guard(value):
        assert value is source
        original_guard(value)
        checks.append(value)

    monkeypatch.setattr(owner, "require_resolved", actual_guard)
    if source_kind == "attempt":
        with _owned_source_episode(reader, current) as episode:
            assert reader._borrow_original_daily(episode, consumer=reader.composer) is current
            assert episode.objects.references[descendant.object_sha256] == descendant
    else:
        # This exact actual source is prospective. Its owned graph is checked,
        # but it cannot seed a historical episode or prove observed-history reuse.
        reader._require_daily_graph(current)
        with (
            pytest.raises(ContinuousIntegrityError, match="COMPLETE_DAILY_VALIDATION_REQUIRED"),
            _owned_source_episode(reader, current),
        ):
            pytest.fail("prospective observed source seeded historical reuse")
    assert checks
    original_owner = getattr(owner, owner_field)
    try:
        setattr(owner, owner_field, object())
        with pytest.raises(ValueError):
            reader._require_daily_graph(current)
    finally:
        setattr(owner, owner_field, original_owner)
    fingerprint = owner._fingerprints[id(source)]
    try:
        owner._fingerprints[id(source)] = "0" * 64
        with pytest.raises(ValueError, match="CONTENT_CHANGED"):
            reader._require_daily_graph(current)
    finally:
        owner._fingerprints[id(source)] = fingerprint
    path = reader.account.artifacts._root / (descendant.object_sha256 + ".json")
    original_payload = path.read_bytes()
    try:
        if source_kind == "attempt":
            with pytest.raises(ValueError), _owned_source_episode(reader, current) as episode:
                reader._borrow_original_daily(episode, consumer=reader.composer)
                path.write_bytes(b"{}")
                reader._borrow_original_daily(episode, consumer=reader.composer)
        else:
            objects = _OriginalObjects(reader.account)
            objects.inspect(current)
            assert objects.references[descendant.object_sha256] == descendant
            path.write_bytes(b"{}")
            with pytest.raises(ValueError):
                objects.recheck()
    finally:
        path.write_bytes(original_payload)
    assert reader._daily_episode is None and reader.composer._integrity_daily is None


def test_final_coherent_sql_and_clock_precede_only_identity_cleanup(case, monkeypatch):
    reader = reader_for(case)
    finished = False
    final_check = reader._recheck_final
    full_guard = reader._require_daily_graph
    object_check = _OriginalObjects.recheck
    artifact_read = reader.account.artifacts.read

    def final(*args):
        nonlocal finished
        final_check(*args)
        finished = True

    def full(*args):
        assert not finished, "full source graph read after final SQL/fence"
        return full_guard(*args)

    def objects(*args):
        assert not finished, "original artifact pass after final SQL/fence"
        return object_check(*args)

    def artifact(*args, **kwargs):
        assert not finished, "artifact I/O after final SQL/fence"
        return artifact_read(*args, **kwargs)

    monkeypatch.setattr(reader, "_recheck_final", final)
    monkeypatch.setattr(reader, "_require_daily_graph", full)
    monkeypatch.setattr(_OriginalObjects, "recheck", objects)
    monkeypatch.setattr(reader.account.artifacts, "read", artifact)
    _validate(reader)
    assert finished and reader._daily_episode is None


def test_cleared_active_binding_denies_without_fresh_read_fallback(case, monkeypatch):
    reader = reader_for(case)
    borrow = reader._borrow_original_daily
    calls = 0

    def cleared(episode, *, consumer):
        nonlocal calls
        calls += 1
        result = borrow(episode, consumer=consumer)
        if calls == 1:
            reader.composer._integrity_daily = None
        return result

    def forbidden_read():
        pytest.fail("damaged active episode fell back to fresh financial read")

    monkeypatch.setattr(reader, "_borrow_original_daily", cleared)
    monkeypatch.setattr(reader.composer, "_current", forbidden_read)
    with pytest.raises(ContinuousIntegrityError):
        _validate(reader)
    assert calls == 2 and reader._daily_episode is None
    assert reader.composer._integrity_daily_active is None


@pytest.mark.parametrize("field", ["_integrity_daily", "_integrity_daily_active"])
def test_caught_binding_failure_cannot_be_repaired_inside_original_episode(case, field):
    reader = reader_for(case)
    current = reader.daily.resolve_snapshot(
        reader.daily.read_snapshot(account_id=reader.scope.account_id, fence=reader.fence)
    )
    with (
        pytest.raises(ContinuousIntegrityError, match="EPISODE_REQUIRED"),
        _owned_source_episode(reader, current),
    ):
        original = getattr(reader.composer, field)
        setattr(reader.composer, field, None)
        with pytest.raises(ValueError, match="BINDING_CHANGED"):
            reader.composer._historical_current()
        setattr(reader.composer, field, original)
        with pytest.raises(ContinuousIntegrityError, match="EPISODE_REQUIRED"):
            reader.composer._historical_current()
    assert reader._daily_episode is None and reader.composer._integrity_daily is None


@pytest.mark.parametrize("slot", ["tuple", "marker"])
def test_foreign_reader_slot_cannot_steal_original_failure_latching(case, slot):
    reader, foreign = reader_for(case), reader_for(case)
    current = reader.daily.resolve_snapshot(
        reader.daily.read_snapshot(account_id=reader.scope.account_id, fence=reader.fence)
    )
    with (
        pytest.raises(ContinuousIntegrityError, match="EPISODE_REQUIRED"),
        _owned_source_episode(reader, current) as episode,
    ):
        field = "_integrity_daily" if slot == "tuple" else "_integrity_daily_active"
        original = getattr(reader.composer, field)
        if slot == "tuple":
            reader.composer._integrity_daily = (foreign, episode)
        else:
            foreign_episode = copy(episode)
            object.__setattr__(foreign_episode, "reader", foreign)
            reader.composer._integrity_daily_active = foreign_episode
        with pytest.raises(ValueError, match="BINDING_CHANGED"):
            reader.composer._historical_current()
        setattr(reader.composer, field, original)
        with pytest.raises(ContinuousIntegrityError, match="EPISODE_REQUIRED"):
            reader.composer._historical_current()
    assert foreign._daily_episode is None and reader._daily_episode is None
    assert reader.composer._integrity_daily is None
