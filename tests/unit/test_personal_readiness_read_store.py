"""Transport/state and finite guards only; fake graph is no financial proof.

The separate integration module opens genuine configured owners and original
SQL readers. This explicit in-memory model exercises only the K state machine
and native/code guards, without opening a file, lease, clock or connection.
"""

import copy
import threading
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace

import pytest

from apps.api import readiness_read_store as read_module
from apps.trader.continuous_readiness_owner import ReadinessCheckResult, ReadinessOwnerStatus
from apps.trader.readiness_store_binding import ReadinessStoreBinding
from packages.domain.continuous_selection_contracts import ContinuousSelectionSnapshot


@pytest.fixture
def transport(monkeypatch):
    model = SimpleNamespace(
        calls=[],
        queries=0,
        disposals=0,
        pool_disposals=0,
        query_entered=threading.Event(),
        query_allowed=threading.Event(),
        disposal_entered=threading.Event(),
        disposal_allowed=threading.Event(),
        primary=None,
        cleanup=None,
        callers=[],
        results=[],
        errors=[],
        terminal=None,
    )
    model.query_allowed.set()
    model.disposal_allowed.set()
    binding = (
        "model-incarnation",
        "model-account",
        "a" * 64,
        "model-stream",
        "/private/tmp/no-transport-file-opened.sqlite",
        0,
        1,
        "b" * 64,
    )

    class ModelOwner:
        def store_binding(self):
            model.calls.append("binding")
            return ReadinessStoreBinding(*binding)

        def check(self, request_id):
            model.calls.append("proof")
            return ReadinessCheckResult("ready", "verified", request_id, binding[0])

        def status(self):
            model.calls.append("status")
            return model.terminal or ReadinessOwnerStatus(
                "idle", False, False, None, None, binding[0]
            )

    class ModelPool:
        def dispose(self):
            model.calls.append("pool-dispose")
            model.pool_disposals += 1

        def recreate(self):
            model.calls.append("pool-recreate")
            return ModelPool()

    class ModelEngine:
        def __init__(self):
            self.url = object()
            self.pool = ModelPool()

        def connect(self):
            raise AssertionError("transport model never opens a connection")

        def dispose(self):
            model.calls.append("dispose")
            model.disposals += 1
            model.disposal_entered.set()
            assert model.disposal_allowed.wait(2), "model disposal barrier was not released"
            self.pool.dispose()
            self.pool = self.pool.recreate()
            if model.cleanup is not None:
                raise model.cleanup

    class ModelReader:
        def __init__(self, engine):
            self.engine = engine

        def read(self, account_id):
            assert account_id == binding[1]
            model.calls.append("query")
            model.queries += 1
            model.query_entered.set()
            assert model.query_allowed.wait(2), "model query barrier was not released"
            if model.primary is not None:
                raise model.primary
            return ContinuousSelectionSnapshot(account_id, "absent", None, None)

    for name, value in {
        "_OWNER": ModelOwner,
        "_OWNER_BINDING": ModelOwner.store_binding,
        "_OWNER_CHECK": ModelOwner.check,
        "_OWNER_STATUS": ModelOwner.status,
        "_ENGINE": ModelEngine,
        "_CONNECT": ModelEngine.connect,
        "_DISPOSE": ModelEngine.dispose,
        "NullPool": ModelPool,
        "_POOL_DISPOSE": ModelPool.dispose,
        "_POOL_RECREATE": ModelPool.recreate,
        "_READER": ModelReader,
        "_READ": ModelReader.read,
    }.items():
        monkeypatch.setattr(read_module, name, value)
    monkeypatch.setattr(read_module, "_physical", lambda values, engine: None)
    # Explicit transport model construction, never a replacement production
    # opener/owner or evidence of genuine financial/schema admission.
    store = object.__new__(read_module.ReadinessReadStore)
    store._identity = store
    store._owner = ModelOwner()
    store._engine = ModelEngine()
    store._reader = ModelReader(store._engine)
    store._binding = binding
    store._lock = threading.Lock()
    store._original = (
        store._owner,
        store._engine,
        store._reader,
        store._engine.url,
        store._engine.pool,
        store._lock,
        binding,
    )
    store._busy = store._closing = False
    store._dispose_started = store._dispose_finished = store._cleanup_failed = False
    store._cleanup_error = None
    model.store = store
    yield model
    model.query_allowed.set()
    model.disposal_allowed.set()
    for caller in model.callers:
        caller.join(3)
        assert not caller.is_alive(), "controlled transport caller did not actually finish"
    # Tests restore each deliberate graph/state substitution before this close.
    store.close()


def _caller(model, operation):
    def invoke():
        try:
            model.results.append(operation())
        except BaseException as error:
            model.errors.append(error)

    caller = threading.Thread(target=invoke)
    model.callers.append(caller)
    caller.start()
    return caller


def test_public_constructor_requires_the_original_resource_opener():
    with pytest.raises(ValueError, match=r"^READINESS_READ_STORE_OPENER_REQUIRED$"):
        read_module.ReadinessReadStore()


@pytest.mark.parametrize("bad", [None, True, object()])
def test_opener_rejects_unowned_arguments_before_effects(bad):
    with pytest.raises(ValueError, match=r"^READINESS_READ_STORE_OWNER_REQUIRED$"):
        read_module.open_readiness_read_store(bad)


def test_copied_resource_is_not_original_and_cannot_read_or_close(transport):
    duplicate = copy.copy(transport.store)
    for operation in (duplicate.read, duplicate.status, duplicate.close):
        with pytest.raises(ValueError, match=r"^READINESS_READ_STORE_ORIGINAL_REQUIRED$"):
            operation()
    assert transport.calls == []


@pytest.mark.parametrize("where", ["class", "instance"])
@pytest.mark.parametrize(
    ("member", "name"),
    [
        ("_owner", "store_binding"),
        ("_owner", "check"),
        ("_owner", "status"),
        ("_reader", "read"),
        ("_engine", "connect"),
        ("_engine", "dispose"),
        ("pool", "dispose"),
        ("pool", "recreate"),
    ],
)
def test_finite_external_method_substitutions_never_run(
    transport, monkeypatch, where, member, name
):
    model = transport
    selected = model.store._engine.pool if member == "pool" else getattr(model.store, member)
    target = type(selected) if where == "class" else selected
    invoked = []

    def replacement(*args, **kwargs):
        invoked.append(name)
        raise AssertionError("substituted external method must not run")

    with monkeypatch.context() as local:
        if where == "class":
            local.setattr(target, name, replacement)
        else:
            assert name not in vars(target)
            local.setitem(vars(target), name, replacement)
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_BINDING_CHANGED$"):
            model.store.read()
        assert invoked == [] and model.calls == []
    if where == "instance":
        assert name not in vars(target)


@pytest.mark.parametrize("where", ["class", "instance"])
def test_workflow_replacement_cannot_bypass_original_read(transport, monkeypatch, where):
    target = type(transport.store) if where == "class" else transport.store
    invoked = []

    def forged_result(*args, **kwargs):
        invoked.append("forged")
        return ContinuousSelectionSnapshot("model-account", "absent", None, None)

    with monkeypatch.context() as local:
        if where == "class":
            local.setattr(target, "_perform_read", forged_result)
        else:
            assert "_perform_read" not in vars(target)
            local.setitem(vars(target), "_perform_read", forged_result)
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_BINDING_CHANGED$"):
            transport.store.read()
        assert invoked == [] and transport.calls == []
        closed = transport.store.close()
        assert closed.cleanup_complete is True and invoked == []
        assert transport.disposals == transport.pool_disposals == 1
    if where == "instance":
        assert "_perform_read" not in vars(target)


@pytest.mark.parametrize(
    ("member", "name"),
    [
        ("store", "_owner"),
        ("store", "_engine"),
        ("store", "_reader"),
        ("reader", "engine"),
        ("engine", "url"),
        ("engine", "pool"),
        ("store", "_binding"),
    ],
)
def test_graph_substitution_denies_before_original_external_calls(transport, member, name):
    store = transport.store
    target = {"store": store, "reader": store._reader, "engine": store._engine}[member]
    original = getattr(target, name)
    replacement = ("different-incarnation", *original[1:]) if name == "_binding" else object()
    setattr(target, name, replacement)
    try:
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_BINDING_CHANGED$"):
            store.read()
        assert transport.calls == []
    finally:
        setattr(target, name, original)


class _HostileText(str):
    def __eq__(self, other):
        raise AssertionError("non-native text operator must not run")

    def strip(self):
        raise AssertionError("non-native text method must not run")


class _HostileInteger(int):
    def __eq__(self, other):
        raise AssertionError("non-native integer operator must not run")

    def __lt__(self, other):
        raise AssertionError("non-native integer comparison must not run")


@pytest.mark.parametrize(
    ("index", "bad"),
    [
        (0, _HostileText("model-incarnation")),
        (1, True),
        (2, "A" * 64),
        (4, "relative"),
        (5, True),
        (5, -1),
        (6, _HostileInteger(1)),
        (7, None),
    ],
)
def test_native_binding_faults_deny_before_equality_or_callbacks(transport, index, bad):
    store = transport.store
    original = store._binding
    changed = list(original)
    changed[index] = bad
    store._binding = tuple(changed)
    try:
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_BINDING_CHANGED$"):
            store.read()
        assert transport.calls == []
    finally:
        store._binding = original


@pytest.mark.parametrize(
    "name", ["_busy", "_closing", "_dispose_started", "_dispose_finished", "_cleanup_failed"]
)
def test_native_state_flags_do_not_accept_integer_coercion(transport, name):
    original = getattr(transport.store, name)
    setattr(transport.store, name, 0)
    try:
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_STATE_INVALID$"):
            transport.store.status()
        assert transport.calls == []
    finally:
        setattr(transport.store, name, original)


def test_status_is_fresh_frozen_and_caller_mutation_does_not_change_cleanup(transport):
    store = transport.store
    first, second = store.status(), store.status()
    assert first == second and first is not second and not hasattr(first, "__dict__")
    with pytest.raises(FrozenInstanceError):
        first.cleanup_complete = True
    object.__setattr__(first, "cleanup_complete", True)
    assert store.status().cleanup_complete is False
    closed = store.close()
    assert closed.phase == "closed" and closed.cleanup_complete is True
    assert transport.disposals == transport.pool_disposals == 1
    assert store.close() == closed and transport.disposals == 1


def test_one_slot_and_one_disposal_remain_owned_until_actual_return(transport):
    model = transport
    model.query_allowed.clear()
    model.disposal_allowed.clear()
    caller = _caller(model, model.store.read)
    try:
        assert model.query_entered.wait(1)
        with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_BUSY$"):
            model.store.read()
        closing = model.store.close()
        assert closing.phase == "closing" and closing.busy and not closing.cleanup_complete
        assert model.disposals == 0
        model.query_allowed.set()
        assert model.disposal_entered.wait(1)
        pending = model.store.close()
        assert pending.phase == "closing" and not pending.busy and not pending.cleanup_complete
        assert model.disposals == 1 and caller.is_alive()
    finally:
        model.query_allowed.set()
        model.disposal_allowed.set()
        caller.join(3)
        assert not caller.is_alive()
    assert model.results == [] and len(model.errors) == 1
    assert str(model.errors[0]) == "READINESS_READ_STORE_CLOSED"
    assert model.store.status().cleanup_complete is True
    assert model.disposals == model.pool_disposals == 1


@pytest.mark.parametrize("mode", ["primary", "cleanup", "both"])
def test_exact_primary_and_deferred_cleanup_errors_are_preserved(transport, mode):
    model = transport
    primary = BaseException("private model query error")
    cleanup = BaseException("private model cleanup error")
    model.primary = primary if mode in ("primary", "both") else None
    model.cleanup = cleanup if mode in ("cleanup", "both") else None
    model.query_allowed.clear()
    caller = _caller(model, model.store.read)
    try:
        assert model.query_entered.wait(1)
        assert model.store.close().cleanup_complete is False
    finally:
        model.query_allowed.set()
        caller.join(3)
        assert not caller.is_alive()
    assert model.results == [] and len(model.errors) == 1
    error = model.errors[0]
    if mode == "primary":
        assert error is primary
    else:
        assert isinstance(error, BaseExceptionGroup)
        assert error.message == "READINESS_READ_STORE_OPERATION_AND_CLEANUP_FAILED"
        assert error.exceptions[1] is cleanup
        if mode == "both":
            assert error.exceptions[0] is primary
        else:
            assert str(error.exceptions[0]) == "READINESS_READ_STORE_CLOSED"
    result = model.store.close()
    assert result.cleanup_complete is (mode == "primary")
    assert result.cleanup_failure == (None if mode == "primary" else "cleanup_failed")
    assert model.disposals == 1


@pytest.mark.parametrize("name", ["dispose", "recreate"])
def test_pool_method_fault_uses_saved_pool_dispose_without_false_engine_completion(
    transport, monkeypatch, name
):
    model = transport
    pool = model.store._engine.pool
    foreign_calls = []

    def foreign(*args, **kwargs):
        foreign_calls.append(name)
        raise AssertionError("substituted pool method must never run")

    with monkeypatch.context() as local:
        assert name not in vars(pool)
        local.setitem(vars(pool), name, foreign)
        with pytest.raises(BaseExceptionGroup) as raised:
            model.store.close()
        assert raised.value.message == "READINESS_READ_STORE_OPERATION_AND_CLEANUP_FAILED"
        assert [str(error) for error in raised.value.exceptions] == [
            "READINESS_READ_STORE_BINDING_CHANGED",
            "READINESS_READ_STORE_CLEANUP_INCOMPLETE",
        ]
        assert foreign_calls == [] and model.disposals == 0 and model.pool_disposals == 1
    assert name not in vars(pool)
    status = model.store.close()
    assert status.phase == "closed" and not status.cleanup_complete
    assert status.cleanup_failure == "cleanup_failed"
    assert model.pool_disposals == 1


@pytest.mark.parametrize(
    "changes", [{"busy": True}, {"phase": "stopping"}, {"incarnation": "other"}]
)
def test_terminal_owner_status_is_an_additional_denial_only(transport, changes):
    transport.terminal = replace(
        ReadinessOwnerStatus("idle", False, False, None, None, "model-incarnation"), **changes
    )
    with pytest.raises(RuntimeError, match=r"^READINESS_READ_STORE_UNAVAILABLE$"):
        transport.store.read()
    assert transport.queries == 1 and transport.calls.count("proof") == 1
