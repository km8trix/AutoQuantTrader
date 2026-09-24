"""Exact original full-schema result transfer, with no weakened source or lease proof."""

import json
from contextlib import contextmanager
from copy import copy
from dataclasses import dataclass, replace
from threading import Thread
from types import MappingProxyType

import pytest

import packages.persistence.continuous_integrity as integrity
from apps.trader.continuous_simulation_factory import ContinuousSimulationFactory
from packages.domain.research_job_contracts import ObjectRef
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.database import DatabaseSchemaNotReady
from tests.integration.test_continuous_simulation_factory import (
    configured as configured,
)
from tests.integration.test_continuous_simulation_factory import release
from tests.integration.test_runtime_owner_associations import install_initial_signed_assignment


@pytest.fixture
def original_factory(configured):
    fixture, config = configured
    install_initial_signed_assignment(fixture)
    release(fixture)
    factory = ContinuousSimulationFactory(
        config, account_id=fixture[0].base.scope.account_id, stop_requested=lambda: False
    )
    try:
        yield fixture, factory
    finally:
        factory.close()


def assert_closed(reader):
    assert reader not in integrity._ACTIVE_FACTORY_READS
    assert reader._factory_read is None
    assert reader._daily_episode is None
    assert reader.composer._integrity_daily is None
    assert reader.composer._integrity_daily_active is None
    assert reader.account.coordinator._state.observations is None


def after_schema(monkeypatch, action):
    original = integrity.verify_operational_schema

    def verify(*args, **kwargs):
        result = original(*args, **kwargs)
        assert result is None
        action(kwargs["continuous_integrity"])
        return result

    monkeypatch.setattr(integrity, "verify_operational_schema", verify)


def test_factory_returns_original_verified_result_without_second_restore(
    original_factory, monkeypatch
):
    fixture, factory = original_factory
    before = fixture[0].counts()
    original_accounts = integrity.SqlContinuousIntegrityReader._validate_accounts
    original_index = SqlContinuousAccount.resolve_index
    actuals = []
    indices = []

    def accounts(reader, *args, **kwargs):
        actual = original_accounts(reader, *args, **kwargs)
        if reader is factory.integrity:
            actuals.append(actual)
        return actual

    def index(store, *args, **kwargs):
        actual = original_index(store, *args, **kwargs)
        if store is factory.account:
            indices.append(actual)
        return actual

    def no_second_restore(*args, **kwargs):
        pytest.fail("factory must consume the actual fully verified result")

    monkeypatch.setattr(integrity.SqlContinuousIntegrityReader, "_validate_accounts", accounts)
    monkeypatch.setattr(SqlContinuousAccount, "resolve_index", index)
    monkeypatch.setattr(factory.account, "restore", no_second_restore)
    result = json.loads(factory.execute(operation_id="original-result-handoff"))
    assert len(actuals) == 1 and actuals[0] is not None
    assert len(indices) >= 2  # Through-anchor and original per-row index guards remain real.
    assert result["sequence"] == actuals[0].receipt.commit.sequence == 1
    assert result["checkpoint_sha256"] == actuals[0].checkpoint.semantic_sha256
    assert result["assignment_generation"] == 1
    assert fixture[0].counts() == before
    assert_closed(factory.integrity)


def test_standalone_schema_validator_keeps_none_result_and_closes_scope(original_factory):
    _fixture, factory = original_factory
    reader = factory.integrity
    original = reader._capture()
    assert original is not None
    assert reader.validate_snapshot(original) is None
    assert_closed(reader)


@pytest.mark.parametrize("replacement", ["clear", "foreign"])
def test_caught_and_repaired_operation_slot_fault_never_falls_back(
    original_factory, monkeypatch, replacement
):
    _fixture, factory = original_factory
    reader = factory.integrity
    original = integrity.verify_operational_schema
    refused = []

    def verify(*args, **kwargs):
        state = reader._factory_read
        reader._factory_read = None if replacement == "clear" else copy(state)
        try:
            original(*args, **kwargs)
        except Exception as error:
            refused.append(error)
        finally:
            reader._factory_read = state
        # A normal schema return cannot repair the hidden original failed call.

    monkeypatch.setattr(integrity, "verify_operational_schema", verify)
    with pytest.raises(integrity.ContinuousIntegrityError):
        reader.verify_original_for_factory()
    assert len(refused) == 1
    assert_closed(reader)


@pytest.mark.parametrize("replacement", ["clear", "foreign"])
def test_completed_callback_cannot_be_repaired_after_nested_slot_fault(
    original_factory, monkeypatch, replacement
):
    _fixture, factory = original_factory
    reader = factory.integrity
    reached = []

    def nested(current):
        state = current._factory_read
        assert state.completed and state.entered == 1
        snapshot = state.result.original
        reached.append("first_schema_completed")
        current._factory_read = None if replacement == "clear" else copy(state)
        try:
            with pytest.raises(integrity.ContinuousIntegrityError):
                current.validate_snapshot(snapshot)
            reached.append("nested_callback_denied")
        finally:
            current._factory_read = state
            reached.append("original_slot_restored")

    after_schema(monkeypatch, nested)
    with pytest.raises(integrity.ContinuousIntegrityError):
        reader.verify_original_for_factory()
    assert reached == ["first_schema_completed", "nested_callback_denied", "original_slot_restored"]
    assert_closed(reader)


def test_nested_operation_latches_before_a_damaged_graph_check(original_factory, monkeypatch):
    _fixture, factory = original_factory
    reader = factory.integrity
    reached = []

    def nested(current):
        reached.append("schema_returned")
        account = current.account
        current.account = object()
        try:
            with pytest.raises(integrity.ContinuousIntegrityError, match="ALREADY_ACTIVE"):
                current.verify_original_for_factory()
            reached.append("nested_denied")
        finally:
            current.account = account

    after_schema(monkeypatch, nested)
    with pytest.raises(integrity.ContinuousIntegrityError):
        reader.verify_original_for_factory()
    assert reached == ["schema_returned", "nested_denied"]
    assert_closed(reader)


def test_wrong_thread_callback_latches_original_operation_before_sql(original_factory, monkeypatch):
    _fixture, factory = original_factory
    reader = factory.integrity
    errors = []

    def wrong_thread(current):
        snapshot = current._factory_read.result.original

        def enter():
            try:
                current.validate_snapshot(snapshot)
            except BaseException as error:
                errors.append(error)

        thread = Thread(target=enter)
        thread.start()
        thread.join(timeout=2)
        assert not thread.is_alive()

    after_schema(monkeypatch, wrong_thread)
    with pytest.raises(integrity.ContinuousIntegrityError):
        reader.verify_original_for_factory()
    assert len(errors) == 1 and isinstance(errors[0], integrity.ContinuousIntegrityError)
    assert_closed(reader)


@pytest.mark.parametrize("kind", ["missing", "duplicate"])
def test_exactly_one_complete_schema_callback_is_required(original_factory, monkeypatch, kind):
    _fixture, factory = original_factory
    reader = factory.integrity
    original = integrity.verify_operational_schema
    calls, completed = [], []

    def verify(*args, **kwargs):
        calls.append("wrapper")
        if kind == "missing":
            return  # Negative-only guard omission cannot issue a result.
        calls.append("first")
        original(*args, **kwargs)
        completed.append("first")
        calls.append("second")
        original(*args, **kwargs)
        completed.append("second")

    monkeypatch.setattr(integrity, "verify_operational_schema", verify)
    with pytest.raises((integrity.ContinuousIntegrityError, DatabaseSchemaNotReady)):
        reader.verify_original_for_factory()
    assert calls == (["wrapper"] if kind == "missing" else ["wrapper", "first", "second"])
    assert completed == ([] if kind == "missing" else ["first"])
    assert_closed(reader)


def test_copied_reader_does_not_gain_an_operation(original_factory):
    _fixture, factory = original_factory
    copied = copy(factory.integrity)
    with pytest.raises(integrity.ContinuousIntegrityError):
        copied.verify_original_for_factory()
    assert_closed(copied)
    assert_closed(factory.integrity)


@pytest.mark.parametrize("mutation", ["copy", "drop", "reference", "total", "snapshot"])
def test_original_proof_and_complete_object_inventory_are_pinned(
    original_factory, monkeypatch, mutation
):
    _fixture, factory = original_factory
    reader = factory.integrity
    applied = []

    def alter(current):
        state = current._factory_read
        result = state.result
        if mutation == "copy":
            state.result = replace(result)
        elif mutation == "drop":
            assert result.objects.references
            result.objects.references.pop(next(iter(result.objects.references)))
        elif mutation == "reference":
            key = next(iter(result.objects.references))
            result.objects.references[key] = replace(result.objects.references[key])
        elif mutation == "total":
            result.objects.total += 1
        else:
            object.__setattr__(
                result.original, "tables", MappingProxyType(dict(result.original.tables))
            )

        applied.append(mutation)

    after_schema(monkeypatch, alter)
    with pytest.raises(integrity.ContinuousIntegrityError):
        reader.verify_original_for_factory()
    assert applied == [mutation]
    assert_closed(reader)


@pytest.mark.parametrize("mutation", ["checkpoint", "objects", "nested_call"])
def test_mutation_during_original_scope_cleanup_cannot_expose_result(
    original_factory, monkeypatch, mutation
):
    _fixture, factory = original_factory
    reader = factory.integrity
    coordinator = reader.account.coordinator
    original_context = type(coordinator).inspect_committed_observations
    saved = []
    applied = []
    after_schema(monkeypatch, lambda current: saved.append(current._factory_read.result))

    @contextmanager
    def inspect(actual_coordinator, *args, **kwargs):
        with original_context(actual_coordinator, *args, **kwargs) as observations:
            yield observations
        if actual_coordinator is not coordinator:
            return
        assert coordinator._state.observations is None
        result = saved[0]
        if mutation == "checkpoint":
            checkpoint = result.actual.checkpoint
            object.__setattr__(
                checkpoint, "remaining_wall_nanoseconds", checkpoint.remaining_wall_nanoseconds - 1
            )
        elif mutation == "objects":
            result.objects.references.clear()
        else:
            with pytest.raises(integrity.ContinuousIntegrityError, match="ALREADY_ACTIVE"):
                reader.verify_original_for_factory()

        applied.append(mutation)

        def no_late_hash(*args, **kwargs):
            pytest.fail("cleanup validation must use the prebuilt identity seal")

        monkeypatch.setattr(integrity, "sha256", no_late_hash)
        monkeypatch.setattr(result.objects, "recheck", no_late_hash)

    monkeypatch.setattr(type(coordinator), "inspect_committed_observations", inspect)
    with pytest.raises(integrity.ContinuousIntegrityError):
        reader.verify_original_for_factory()
    assert len(saved) == 1
    assert applied == [mutation]
    assert_closed(reader)


class OriginalStop(BaseException):
    pass


class CleanupStop(BaseException):
    pass


@pytest.mark.parametrize("primary", [False, True])
def test_original_failure_remains_primary_when_original_close_also_fails(
    original_factory, monkeypatch, primary
):
    _fixture, factory = original_factory
    reader = factory.integrity
    coordinator = reader.account.coordinator
    original_context = type(coordinator).inspect_committed_observations
    first, closing = OriginalStop(), CleanupStop()

    @contextmanager
    def inspect(actual_coordinator, *args, **kwargs):
        with original_context(actual_coordinator, *args, **kwargs) as observations:
            yield observations
        if actual_coordinator is not coordinator:
            return
        raise closing

    monkeypatch.setattr(type(coordinator), "inspect_committed_observations", inspect)
    if primary:

        def fail(current):
            raise first

        after_schema(monkeypatch, fail)
    with pytest.raises(BaseException) as caught:
        reader.verify_original_for_factory()
    assert caught.value is (first if primary else closing)
    assert_closed(reader)


@dataclass
class StructureNode:
    value: object


@dataclass
class SameLayout:
    value: object


def test_mechanical_seal_tracks_aliases_cycles_and_nested_mutation():
    ref = ObjectRef("a" * 64, 1, "personal-record/1")
    node = StructureNode(ref)
    cyclic = {"node": node, "alias": node}
    cyclic["cycle"] = cyclic
    records = integrity._factory_structure((cyclic,))
    integrity._require_factory_structure(records)
    object.__setattr__(ref, "byte_count", 2)
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_CHANGED"):
        integrity._require_factory_structure(records)


def test_mechanical_seal_rejects_identical_layout_class_substitution():
    node = StructureNode("original")
    records = integrity._factory_structure((node,))
    node.__class__ = SameLayout
    with pytest.raises(integrity.ContinuousIntegrityError, match="TYPE_CHANGED"):
        integrity._require_factory_structure(records)


@pytest.mark.parametrize("bound", ["edges", "containers"])
def test_mechanical_seal_explicit_handoff_caps_deny_before_large_binding_copy(monkeypatch, bound):
    if bound == "edges":
        monkeypatch.setattr(integrity, "_MAX_FACTORY_BINDINGS", 4)
        value = (None,) * 5
    else:
        monkeypatch.setattr(integrity, "_MAX_FACTORY_CONTAINERS", 1)
        value = (("one",), ("two",))
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_BOUND"):
        integrity._factory_structure((value,))


def test_mechanical_seal_rejects_unknown_mutable_leaves():
    with pytest.raises(integrity.ContinuousIntegrityError, match="UNKNOWN_MUTABLE"):
        integrity._factory_structure((bytearray(b"mutable"),))


def test_competing_operation_after_final_close_seal_poisons_atomic_retirement(
    original_factory, monkeypatch
):
    _fixture, factory = original_factory
    reader = factory.integrity
    original = integrity._require_factory_structure
    errors = []
    attempted = False

    def recheck(records):
        nonlocal attempted
        original(records)
        state = reader._factory_read
        if (
            attempted
            or state is None
            or not state.failed
            or reader.account.coordinator._state.observations is not None
        ):
            return
        attempted = True

        def competing():
            try:
                reader.verify_original_for_factory()
            except BaseException as error:
                errors.append(error)

        thread = Thread(target=competing)
        thread.start()
        thread.join(timeout=2)
        assert not thread.is_alive()

    monkeypatch.setattr(integrity, "_require_factory_structure", recheck)
    with pytest.raises(integrity.ContinuousIntegrityError):
        reader.verify_original_for_factory()
    assert attempted and len(errors) == 1
    assert isinstance(errors[0], integrity.ContinuousIntegrityError)
    assert_closed(reader)


def test_mechanical_seal_pins_only_the_exact_original_sql_name_profile():
    from sqlalchemy.sql.elements import quoted_name

    name = quoted_name("original_column", True)
    records = integrity._factory_structure((name,))
    integrity._require_factory_structure(records)
    name.quote = False
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_CHANGED"):
        integrity._require_factory_structure(records)

    class OtherString(str):
        pass

    with pytest.raises(integrity.ContinuousIntegrityError, match="UNKNOWN_MUTABLE"):
        integrity._factory_structure((OtherString("original_column"),))


def test_mechanical_seal_known_owner_profile_is_exact_and_does_not_admit_copies(original_factory):
    _fixture, factory = original_factory
    records = integrity._factory_structure(
        (StructureNode(factory.account), StructureNode(factory.daily)),
        account=factory.account,
        daily=factory.daily,
    )
    integrity._require_factory_structure(records)
    for owner in (factory.account, factory.daily):
        with pytest.raises(integrity.ContinuousIntegrityError, match="UNKNOWN_MUTABLE"):
            integrity._factory_structure(
                (StructureNode(copy(owner)),), account=factory.account, daily=factory.daily
            )


def test_mechanical_seal_sql_name_rejects_non_boolean_quote_flag():
    from sqlalchemy.sql.elements import quoted_name

    name = quoted_name("original_column", True)
    name.quote = 1
    with pytest.raises(integrity.ContinuousIntegrityError, match="QUOTE_INVALID"):
        integrity._factory_structure((name,))


def test_mechanical_seal_pins_original_selected_sql_bind_values():
    from packages.persistence.daily_runtime_risk_schema import daily_runtime_consumptions

    selected = daily_runtime_consumptions.c.attempt_id.in_(("original-attempt",))
    records = integrity._factory_structure((selected,))
    integrity._require_factory_structure(records)
    selected.right.value.append("changed-attempt")
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_CHANGED"):
        integrity._require_factory_structure(records)


def test_mechanical_seal_checks_declared_column_quoting_without_walking_metadata(monkeypatch):
    from packages.persistence.daily_runtime_risk_schema import daily_runtime_consumptions

    name = daily_runtime_consumptions.c.attempt_id.name
    records = integrity._factory_structure((daily_runtime_consumptions,))
    integrity._require_factory_structure(records)
    monkeypatch.setattr(name, "quote", not name.quote)
    with pytest.raises(integrity.ContinuousIntegrityError, match="STRUCTURE_CHANGED"):
        integrity._require_factory_structure(records)
