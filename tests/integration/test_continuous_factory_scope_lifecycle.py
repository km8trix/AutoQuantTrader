"""Owned HALTED genesis scope faults; pure seal cases grant no financial authority."""

from contextlib import contextmanager
from copy import copy
from threading import Thread

import pytest

import packages.persistence.continuous_integrity as integrity
from tests.integration.test_continuous_factory_integrity_result import (
    assert_closed,
)
from tests.integration.test_continuous_factory_integrity_result import (
    configured as configured,
)
from tests.integration.test_continuous_factory_integrity_result import (
    original_factory as original_factory,
)


def _complete(reader):
    reader.require_original_factory_values()
    current = reader.read_original_daily_for_factory()
    reader.require_original_factory_values()
    return current


def _cleanup_fault(monkeypatch, reader, action):
    coordinator = reader.account.coordinator
    cls = type(coordinator)
    original = cls.inspect_committed_observations

    @contextmanager
    def observe(actual, *args, **kwargs):
        with original(actual, *args, **kwargs) as observations:
            yield observations
        if actual is coordinator:
            action()

    monkeypatch.setattr(cls, "inspect_committed_observations", observe)


def test_terminal_is_once_after_provisional_body_and_returns_original_b(
    original_factory, monkeypatch
):
    _fixture, factory = original_factory
    reader = factory.integrity
    original = type(reader)._verify_factory_terminal
    reached = []

    def terminal(actual, state, result):
        if actual is reader:
            reached.append("terminal")
        return original(actual, state, result)

    monkeypatch.setattr(type(reader), "_verify_factory_terminal", terminal)
    wrapper = reader.original_factory_read()
    with wrapper as actual:
        assert reached == []
        state = reader._factory_read
        assert state.result.actual is actual
        assert reader.composer._integrity_daily is None
        assert reader.composer._integrity_daily_active is None
        assert reader.account.coordinator._state.observations is not None
        current = _complete(reader)
        assert current is state.result.current
        assert state.final_read.raw is not current.raw
        assert state.final_read.structure[: len(state.result.structure)] == state.result.structure
        assert reached == []
        reached.append("body")
    assert reached == ["body", "terminal"]
    assert integrity._FACTORY_SCOPES[wrapper].closed
    assert_closed(reader)
    with pytest.raises(integrity.ContinuousIntegrityError):
        wrapper.__enter__()


def test_standalone_transfer_still_finishes_terminal_before_return(original_factory, monkeypatch):
    _fixture, factory = original_factory
    reader = factory.integrity
    original = type(reader)._verify_factory_terminal
    reached = []

    def terminal(actual, state, result):
        if actual is reader:
            assert state.scope is None
            reached.append("terminal")
        return original(actual, state, result)

    monkeypatch.setattr(type(reader), "_verify_factory_terminal", terminal)
    actual = reader.verify_original_for_factory()
    assert actual.receipt.commit.sequence == 1
    assert reached == ["terminal"]
    assert_closed(reader)


def test_skipped_final_read_cannot_finish_scope(original_factory):
    _fixture, factory = original_factory
    reader = factory.integrity
    reached = []
    with pytest.raises(integrity.ContinuousIntegrityError), reader.original_factory_read():
        reached.append("body")
    assert reached == ["body"]
    assert_closed(reader)


def test_caught_duplicate_read_poison_is_not_repaired_by_returning_to_body(original_factory):
    _fixture, factory = original_factory
    reader = factory.integrity
    reached = []
    with pytest.raises(integrity.ContinuousIntegrityError), reader.original_factory_read():
        _complete(reader)
        with pytest.raises(integrity.ContinuousIntegrityError):
            reader.read_original_daily_for_factory()
        reached.append("duplicate_denied")
    assert reached == ["duplicate_denied"]
    assert_closed(reader)


def test_caught_same_wrapper_reentry_poison_reaches_original_cleanup(original_factory):
    _fixture, factory = original_factory
    reader = factory.integrity
    wrapper = reader.original_factory_read()
    reached = []
    with pytest.raises(integrity.ContinuousIntegrityError), wrapper:
        _complete(reader)
        with pytest.raises(integrity.ContinuousIntegrityError):
            wrapper.__enter__()
        reached.append("reentry_denied")
    assert reached == ["reentry_denied"]
    assert_closed(reader)


@pytest.mark.parametrize("method", ["enter", "exit"])
def test_foreign_thread_wrapper_misuse_latches_but_owner_performs_cleanup(original_factory, method):
    _fixture, factory = original_factory
    reader = factory.integrity
    wrapper = reader.original_factory_read()
    errors = []

    def foreign():
        try:
            if method == "enter":
                wrapper.__enter__()
            else:
                wrapper.__exit__(None, None, None)
        except BaseException as error:
            errors.append(error)

    with pytest.raises(integrity.ContinuousIntegrityError), wrapper:
        _complete(reader)
        worker = Thread(target=foreign)
        worker.start()
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], integrity.ContinuousIntegrityError)
        # Foreign exit did not drive the context on the wrong thread.
        assert reader in integrity._ACTIVE_FACTORY_READS
        assert reader.account.coordinator._state.observations is not None
    assert_closed(reader)


@pytest.mark.parametrize("field", ["reader", "thread", "manager", "originals", "phase"])
def test_owner_exit_cleans_original_manager_after_mutable_wrapper_damage(original_factory, field):
    _fixture, factory = original_factory
    reader = factory.integrity
    wrapper = reader.original_factory_read()
    reached = []
    with pytest.raises(integrity.ContinuousIntegrityError), wrapper:
        _complete(reader)
        scope = integrity._FACTORY_SCOPES[wrapper].state
        setattr(scope, field, () if field == "originals" else object())
        reached.append(field)
    assert reached == [field]
    assert integrity._FACTORY_SCOPES[wrapper].closed
    assert_closed(reader)


@pytest.mark.parametrize("latched", [False, True])
def test_body_baseexception_survives_wrapper_and_cleanup_errors(
    original_factory, monkeypatch, latched
):
    _fixture, factory = original_factory
    reader = factory.integrity
    wrapper = reader.original_factory_read()
    primary = KeyboardInterrupt("owned fixture primary")
    reached = []

    def cleanup():
        reached.append("cleanup")
        raise ValueError("owned fixture cleanup")

    _cleanup_fault(monkeypatch, reader, cleanup)
    with pytest.raises(KeyboardInterrupt) as caught, wrapper:
        _complete(reader)
        if latched:
            with pytest.raises(integrity.ContinuousIntegrityError):
                wrapper.__enter__()
        integrity._FACTORY_SCOPES[wrapper].state.manager = object()
        reached.append("body")
        raise primary
    assert caught.value is primary
    assert reached == ["body", "cleanup"]
    assert_closed(reader)


def test_comparison_primary_survives_cleanup_failure(original_factory, monkeypatch):
    _fixture, factory = original_factory
    reader = factory.integrity
    cls = type(reader.daily)
    original = cls.require_same_complete_capture
    primary = RuntimeError("owned comparison primary")
    reached = []

    def compare(actual, old, fresh):
        result = original(actual, old, fresh)
        if actual is reader.daily:
            reached.append("comparison")
            raise primary
        return result

    def cleanup():
        reached.append("cleanup")
        raise ValueError("owned cleanup failure")

    monkeypatch.setattr(cls, "require_same_complete_capture", compare)
    _cleanup_fault(monkeypatch, reader, cleanup)
    with pytest.raises(RuntimeError) as caught, reader.original_factory_read():
        reader.read_original_daily_for_factory()
    assert caught.value is primary
    assert reached == ["comparison", "cleanup"]
    assert_closed(reader)


def test_final_metadata_cannot_be_cleared_after_successful_terminal(original_factory, monkeypatch):
    _fixture, factory = original_factory
    reader = factory.integrity
    original = type(reader)._verify_factory_terminal
    reached = []

    def terminal(actual, state, result):
        outcome = original(actual, state, result)
        if actual is reader:
            reached.append("terminal_completed")
            state.final_started = False
            state.final_completed = False
            state.final_read = None
            state.final_fields = ()
        return outcome

    monkeypatch.setattr(type(reader), "_verify_factory_terminal", terminal)
    with pytest.raises(integrity.ContinuousIntegrityError), reader.original_factory_read():
        _complete(reader)
    assert reached == ["terminal_completed"]
    assert_closed(reader)


def test_final_metadata_mutation_during_original_close_denies_result(original_factory, monkeypatch):
    _fixture, factory = original_factory
    reader = factory.integrity
    saved = []
    reached = []

    def cleanup():
        assert len(saved) == 1
        saved[0].final_fields = ()
        reached.append("cleanup_mutation")

    _cleanup_fault(monkeypatch, reader, cleanup)
    with pytest.raises(integrity.ContinuousIntegrityError), reader.original_factory_read():
        _complete(reader)
        saved.append(reader._factory_read)
    assert reached == ["cleanup_mutation"]
    assert_closed(reader)


@pytest.mark.parametrize("field", ["raw", "structure"])
def test_original_final_metadata_object_cannot_change_during_close(
    original_factory, monkeypatch, field
):
    _fixture, factory = original_factory
    reader = factory.integrity
    saved = []
    reached = []

    def cleanup():
        assert len(saved) == 1
        final = saved[0]
        replacement = copy(final.raw) if field == "raw" else tuple(list(final.structure))
        assert replacement is not getattr(final, field)
        object.__setattr__(final, field, replacement)
        reached.append(field)

    _cleanup_fault(monkeypatch, reader, cleanup)
    with pytest.raises(integrity.ContinuousIntegrityError), reader.original_factory_read():
        _complete(reader)
        saved.append(reader._factory_read.final_read)
    assert reached == [field]
    assert_closed(reader)


def test_copied_wrapper_is_denied_without_revoking_original_scope(original_factory):
    _fixture, factory = original_factory
    reader = factory.integrity
    wrapper = reader.original_factory_read()
    duplicate = copy(wrapper)
    with wrapper:
        _complete(reader)
        with pytest.raises(integrity.ContinuousIntegrityError):
            duplicate.__enter__()
    assert_closed(reader)


def test_original_and_fresh_seals_keep_one_aggregate_binding_bound(monkeypatch):
    # Profile 2 expands only retained container inventory, not the edge budget.
    old = ([1, 2, 3], (), {})
    fresh = [4, 5, 6]
    original = integrity._factory_structure(old)
    original_edges = 3 + sum(len(record[4]) for record in original)
    monkeypatch.setattr(integrity, "_MAX_FACTORY_BINDINGS", original_edges)
    integrity._factory_structure((fresh,))
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_BOUND"):
        integrity._factory_structure((fresh,), original=original)


def test_extension_preserves_original_field_records_instead_of_resealing():
    old_list = [object()]
    original = integrity._factory_structure((old_list, (), {}))
    old_list[0] = object()
    combined = integrity._factory_structure(([old_list],), original=original)
    assert all(a is b for a, b in zip(combined, original, strict=False))
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_CHANGED"):
        integrity._require_factory_structure(combined)


@pytest.mark.parametrize("field", ["phase", "reader", "thread", "manager", "originals"])
@pytest.mark.parametrize("body_primary", [False, True])
def test_deleted_wrapper_slot_still_closes_original_manager(
    original_factory, monkeypatch, field, body_primary
):
    _fixture, factory = original_factory
    reader = factory.integrity
    wrapper = reader.original_factory_read()
    primary = KeyboardInterrupt("original body before deleted-wrapper cleanup")
    reached = []

    def cleanup():
        reached.append("original_close")
        if body_primary:
            raise ValueError("later original cleanup failure")

    _cleanup_fault(monkeypatch, reader, cleanup)
    expected = KeyboardInterrupt if body_primary else AttributeError
    with pytest.raises(expected) as caught, wrapper:
        _complete(reader)
        scope = integrity._FACTORY_SCOPES[wrapper].state
        object.__delattr__(scope, field)
        assert not hasattr(scope, field)
        reached.append("deleted")
        if body_primary:
            raise primary
    if body_primary:
        assert caught.value is primary
    else:
        assert caught.value.name == field
    assert reached == ["deleted", "original_close"]
    assert integrity._FACTORY_SCOPES[wrapper].closed
    assert_closed(reader)


@pytest.mark.parametrize(
    ("target", "field"),
    [
        ("state", "final_started"),
        ("state", "final_completed"),
        ("state", "final_read"),
        ("state", "final_fields"),
        ("result", "structure"),
        ("final", "raw"),
        ("final", "structure"),
    ],
)
@pytest.mark.parametrize("body_primary", [False, True])
def test_deleted_operation_metadata_cannot_skip_close_or_retirement(
    original_factory, monkeypatch, target, field, body_primary
):
    _fixture, factory = original_factory
    reader = factory.integrity
    wrapper = reader.original_factory_read()
    primary = KeyboardInterrupt("original body before deleted-metadata cleanup")
    reached = []

    def cleanup():
        reached.append("original_close")
        if body_primary:
            raise ValueError("later original cleanup failure")

    _cleanup_fault(monkeypatch, reader, cleanup)
    expected = KeyboardInterrupt if body_primary else AttributeError
    with pytest.raises(expected) as caught, wrapper:
        _complete(reader)
        state = reader._factory_read
        value = {"state": state, "result": state.result, "final": state.final_read}[target]
        object.__delattr__(value, field)
        assert not hasattr(value, field)
        reached.append("deleted")
        if body_primary:
            raise primary
    if body_primary:
        assert caught.value is primary
    else:
        assert caught.value.name == field
    assert reached == ["deleted", "original_close"]
    assert integrity._FACTORY_SCOPES[wrapper].closed
    assert_closed(reader)


@pytest.mark.parametrize("field", ["raw", "structure"])
def test_original_final_slot_deleted_after_terminal_is_denied_after_close(
    original_factory, monkeypatch, field
):
    _fixture, factory = original_factory
    reader = factory.integrity
    saved = []
    reached = []
    original = type(reader)._verify_factory_terminal

    def terminal(actual, state, result):
        outcome = original(actual, state, result)
        if actual is reader:
            reached.append("terminal_completed")
        return outcome

    def cleanup():
        assert len(saved) == 1
        final = saved[0]
        object.__delattr__(final, field)
        assert not hasattr(final, field)
        reached.append("original_close_deleted")

    monkeypatch.setattr(type(reader), "_verify_factory_terminal", terminal)
    _cleanup_fault(monkeypatch, reader, cleanup)
    with pytest.raises(AttributeError) as caught, reader.original_factory_read():
        _complete(reader)
        saved.append(reader._factory_read.final_read)
    assert caught.value.name == field
    assert reached == ["terminal_completed", "original_close_deleted"]
    assert_closed(reader)


@pytest.mark.parametrize("operation_field", ["scope", "faults"])
@pytest.mark.parametrize("body_primary", [False, True])
def test_failed_fault_marker_cannot_skip_original_wrapper_cleanup(
    original_factory, monkeypatch, operation_field, body_primary
):
    _fixture, factory = original_factory
    reader = factory.integrity
    wrapper = reader.original_factory_read()
    primary = KeyboardInterrupt("body failure before fault-marker failure")
    reached = []

    def cleanup():
        reached.append("original_close")
        raise ValueError("later cleanup failure must not replace the first failure")

    _cleanup_fault(monkeypatch, reader, cleanup)
    expected = KeyboardInterrupt if body_primary else AttributeError
    with pytest.raises(expected) as caught, wrapper:
        _complete(reader)
        scope = integrity._FACTORY_SCOPES[wrapper].state
        operation = reader._factory_read
        object.__delattr__(scope, "phase")
        object.__delattr__(operation, operation_field)
        assert not hasattr(scope, "phase")
        assert not hasattr(operation, operation_field)
        reached.append("both_deleted")
        if body_primary:
            raise primary
    if body_primary:
        assert caught.value is primary
    else:
        assert caught.value.name == "phase"
    assert reached == ["both_deleted", "original_close"]
    assert integrity._FACTORY_SCOPES[wrapper].closed
    assert_closed(reader)


@pytest.mark.parametrize("operation_field", ["scope", "faults"])
def test_entry_fault_marker_failure_still_closes_the_yielded_original_manager(
    original_factory, monkeypatch, operation_field
):
    _fixture, factory = original_factory
    reader = factory.integrity
    reached = []
    original = reader._factory_operation

    @contextmanager
    def operation(*, scope=None):
        with original(scope=scope) as result:
            wrapper_state = integrity._FACTORY_SCOPES[scope].state
            object.__delattr__(wrapper_state, "phase")
            object.__delattr__(reader._factory_read, operation_field)
            reached.append("original_yielded_then_both_deleted")
            yield result

    def cleanup():
        reached.append("original_close")
        raise ValueError("later cleanup failure must not replace entry failure")

    monkeypatch.setattr(reader, "_factory_operation", operation)
    _cleanup_fault(monkeypatch, reader, cleanup)
    wrapper = reader.original_factory_read()
    with pytest.raises(AttributeError) as caught:
        wrapper.__enter__()
    assert caught.value.name == "phase"
    assert reached == ["original_yielded_then_both_deleted", "original_close"]
    assert integrity._FACTORY_SCOPES[wrapper].closed
    assert_closed(reader)


@pytest.mark.parametrize("body_primary", [False, True])
def test_post_close_fault_marker_cannot_replace_primary_or_closing_denial(
    original_factory, monkeypatch, body_primary
):
    _fixture, factory = original_factory
    reader = factory.integrity
    wrapper = reader.original_factory_read()
    primary = KeyboardInterrupt("body failure before post-close marker failure")
    reached = []
    original_mark = integrity._fail_factory_scope

    def cleanup():
        reached.append("original_close")
        integrity._FACTORY_SCOPES[wrapper].state.phase = "changed_during_close"

    def fail_after_original_mark(actual_wrapper, owner):
        assert actual_wrapper is wrapper
        assert reader not in integrity._ACTIVE_FACTORY_READS
        assert reader.account.coordinator._state.observations is None
        original_mark(actual_wrapper, owner)
        reached.append("post_close_marker")
        raise ValueError("injected secondary marker failure after original retirement")

    _cleanup_fault(monkeypatch, reader, cleanup)
    monkeypatch.setattr(integrity, "_fail_factory_scope", fail_after_original_mark)
    expected = KeyboardInterrupt if body_primary else integrity.ContinuousIntegrityError
    with pytest.raises(expected) as caught, wrapper:
        _complete(reader)
        if body_primary:
            raise primary
    if body_primary:
        assert caught.value is primary
    else:
        assert str(caught.value) == "ORIGINAL_FACTORY_SCOPE_CLOSING_CHANGED"
    assert reached == ["original_close", "post_close_marker"]
    assert integrity._FACTORY_SCOPES[wrapper].closed
    assert_closed(reader)


def test_two_capture_profile_keeps_initial_limit_and_accepts_exact_joint_limit():
    # Pure distinct empty lists exercise actual production limits without SQL,
    # decoding, account owners or financial authority.
    old = ([[] for _ in range(16_384 - 3)], (), {})
    original = integrity._factory_structure(old)
    assert len(original) == 16_384
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_BOUND"):
        integrity._factory_structure(([*old[0], []], old[1], old[2]))
    fresh = [[] for _ in range(16_384 - 1)]
    combined = integrity._factory_structure((fresh,), original=original)
    assert len(combined) == 32_768
    assert all(combined[index] is record for index, record in enumerate(original))
    integrity._require_factory_structure(combined)
    fresh.append([])
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_BOUND"):
        integrity._factory_structure((fresh,), original=original)


def test_fresh_capture_limit_applies_when_joint_inventory_still_has_room():
    original = integrity._factory_structure(([], (), {}))
    fresh = [[] for _ in range(16_384 - 1)]
    combined = integrity._factory_structure((fresh,), original=original)
    assert len(combined) == len(original) + 16_384 < 32_768
    integrity._require_factory_structure(combined)
    fresh.append([])
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_BOUND"):
        integrity._factory_structure((fresh,), original=original)


def test_joint_inventory_limit_applies_before_either_capture_limit(monkeypatch):
    original = integrity._factory_structure(([], (), {}))
    fresh = [[]]
    assert len(original) == 3
    assert len(integrity._factory_structure((fresh,))) == 2
    monkeypatch.setattr(integrity, "_MAX_FACTORY_COMBINED_CONTAINERS", 4)
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_BOUND"):
        integrity._factory_structure((fresh,), original=original)


def test_oversized_original_inventory_is_rejected_before_visiting_records():
    # None cannot be read as a binding; reaching it would fail with TypeError.
    # The inventory bound must be checked before such access or list/set copies.
    oversized = (None,) * (16_384 + 1)
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_BOUND"):
        integrity._factory_structure(([],), original=oversized)


def test_original_identity_dedup_does_not_spend_a_fresh_record(monkeypatch):
    shared = [object()]
    original = integrity._factory_structure((shared, (), {}))
    fresh = [shared] * 1_024
    monkeypatch.setattr(integrity, "_MAX_FACTORY_FRESH_CONTAINERS", 1)
    combined = integrity._factory_structure((fresh,), original=original)
    assert len(combined) == len(original) + 1
    assert all(combined[index] is record for index, record in enumerate(original))
    integrity._require_factory_structure(combined)
    fresh.append([])
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_BOUND"):
        integrity._factory_structure((fresh,), original=original)


def test_exact_joint_binding_limit_still_counts_both_captures():
    original = integrity._factory_structure(([0] * 65_534, (), {}))
    fresh = [0] * 65_534
    combined = integrity._factory_structure((fresh,), original=original)
    assert 4 + sum(len(record[4]) for record in combined) == 131_072
    integrity._require_factory_structure(combined)
    fresh.append(0)
    # The fresh data independently fits. Its additional edge still exceeds the
    # unchanged joint budget when the original capture remains retained.
    integrity._factory_structure((fresh,))
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_BOUND"):
        integrity._factory_structure((fresh,), original=original)


@pytest.mark.parametrize("capture", ["original", "fresh"])
def test_two_capture_profile_still_denies_mutation_in_either_capture(capture):
    old_list = [object()]
    fresh = [object()]
    original = integrity._factory_structure((old_list, (), {}))
    combined = integrity._factory_structure((fresh,), original=original)
    integrity._require_factory_structure(combined)
    target = old_list if capture == "original" else fresh
    target[0] = object()
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_CHANGED"):
        integrity._require_factory_structure(combined)
