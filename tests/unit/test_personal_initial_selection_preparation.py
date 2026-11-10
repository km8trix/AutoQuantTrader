"""Native/state transport only; no Runtime or preparation success is fabricated.

Getter carriers below are deliberately allocated without the adapter constructor.
They exercise only detached historical metadata and identity/Thread admission.
Genuine configured owners, full proofs, puts and reentry are separate integrations.
"""

import builtins
import copy
import socket
import sqlite3
import subprocess
import threading
import time
from dataclasses import fields
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import Engine

from apps.trader import initial_selection_preparation as preparation
from apps.trader.initial_selection_descriptor import InitialSelectionDescriptor

_INVALID = "^INITIAL_SELECTION_PREPARATION_INVALID$"
_MAX_NS = 2**63 - 1


def _descriptor():
    return InitialSelectionDescriptor(
        account_id="native-preparation-account",
        account_binding_sha256="0" * 64,
        stream_id="native-preparation-stream",
        after_assignment_sha256="1" * 64,
        ledger_sha256="2" * 64,
        order_sha256="3" * 64,
        capacity_sha256="4" * 64,
        effect_watermark=7,
        attempt_sha256="5" * 64,
        control_revision=11,
        lease_generation=13,
        dependency_schema_id="runtime-owner-dependencies/1",
        dependency_object_sha256="6" * 64,
        dependency_byte_count=1024,
        dependency_codec_version="personal-record/1",
        dependency_semantic_sha256="7" * 64,
        checked_at=datetime(2026, 10, 28, 14, 0, tzinfo=UTC),
        valid_until=datetime(2026, 10, 28, 14, 0, 30, tzinfo=UTC),
        c1_receipt_sha256="8" * 64,
        control_sha256="9" * 64,
        original_lease_sha256="a" * 64,
    )


def _values(record):
    return tuple(getattr(record, field.name) for field in fields(record))


def _getter_carrier(*, attempted=True, values=None):
    # This does not qualify __init__, factory provenance, bindings or a prepared
    # dependency. No Runtime is constructed, borrowed or accepted as genuine.
    value = object.__new__(preparation._InitialSelectionPreparation)
    value._instance = value
    value._thread = threading.current_thread()
    value._attempted = attempted
    value._descriptor_values = values
    return value


@pytest.mark.parametrize("deadline", [1, _MAX_NS])
def test_native_deadline_helper_keeps_exact_positive_original_range(deadline):
    assert preparation._deadline(deadline) == deadline
    assert type(preparation._deadline(deadline)) is int


@pytest.mark.parametrize(
    "kind",
    [
        "zero",
        "negative",
        "true",
        "false",
        "float",
        "nan",
        "text",
        "null",
        "object",
        "over",
        "subclass",
    ],
)
def test_native_deadline_helper_rejects_without_coercion_or_user_operators(kind):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("operator")
        raise AssertionError("deadline admission invoked a user operator")

    class HostileInt(int):
        __eq__ = forbidden
        __lt__ = forbidden
        __le__ = forbidden
        __gt__ = forbidden
        __ge__ = forbidden
        __int__ = forbidden
        __index__ = forbidden

    invalid = {
        "zero": 0,
        "negative": -1,
        "true": True,
        "false": False,
        "float": 1.0,
        "nan": float("nan"),
        "text": "1",
        "null": None,
        "object": object(),
        "over": _MAX_NS + 1,
        "subclass": HostileInt(1),
    }[kind]
    with pytest.raises(ValueError, match=_INVALID) as caught:
        preparation._deadline(invalid)
    assert type(caught.value) is ValueError
    assert calls == []


@pytest.mark.parametrize("attempted", [False, True], ids=["before-attempt", "failed-attempt"])
def test_historical_getter_without_success_does_not_touch_runtime_or_clock(monkeypatch, attempted):
    value = _getter_carrier(attempted=attempted)
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("historical getter attempted live work")

    with monkeypatch.context() as local:
        for target, name in ((time, "monotonic_ns"), (time, "time"), (Engine, "connect")):
            local.setattr(target, name, forbidden)
        assert value.descriptor() is None
    assert value._attempted is attempted
    assert value._descriptor_values is None
    assert effects == []


def test_historical_getter_exports_fresh_native_copies_without_live_resources(monkeypatch):
    expected = _descriptor()
    baseline = _values(expected)
    value = _getter_carrier(values=baseline)
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("historical data getter reached an effect")

    # No _runtime/_prepared/_fingerprint fields exist on this transport carrier.
    # Returning metadata must not require them, including after a real context
    # has closed (the genuine post-close case is an integration, not this model).
    with monkeypatch.context() as local:
        for target, name in (
            (builtins, "open"),
            (Path, "open"),
            (Path, "read_bytes"),
            (Path, "write_bytes"),
            (socket, "socket"),
            (sqlite3, "connect"),
            (subprocess, "Popen"),
            (Engine, "connect"),
            (time, "time"),
            (time, "monotonic"),
            (time, "monotonic_ns"),
        ):
            local.setattr(target, name, forbidden)
        first = value.descriptor()
        second = value.descriptor()
    assert type(first) is type(second) is InitialSelectionDescriptor
    assert first == second == expected
    assert first is not second and first is not expected
    object.__setattr__(first, "account_id", "caller-changed")
    object.__setattr__(first, "dependency_byte_count", 0)
    object.__setattr__(first, "checked_at", datetime(2027, 1, 1, tzinfo=UTC))
    third = value.descriptor()
    assert third == second == expected
    assert third is not second
    assert value._descriptor_values is baseline and value._descriptor_values == baseline
    assert effects == []


@pytest.mark.parametrize("bad", [0, 1, None, "attempted"])
def test_historical_getter_rejects_non_native_attempt_state(bad):
    value = _getter_carrier(attempted=bad)
    with pytest.raises(ValueError, match=_INVALID):
        value.descriptor()


def test_historical_getter_rejects_non_native_baseline_container():
    value = _getter_carrier(values=[])
    with pytest.raises(ValueError, match=_INVALID):
        value.descriptor()


@pytest.mark.parametrize("bad", [(), ("short",)])
def test_historical_getter_preserves_original_descriptor_validation_error(bad):
    value = _getter_carrier(values=bad)
    with pytest.raises(ValueError, match=r"^INITIAL_SELECTION_DESCRIPTOR_INVALID$"):
        value.descriptor()


def test_copied_adapter_cannot_export_original_getter_state_and_does_not_poison_it():
    expected = _descriptor()
    original = _getter_carrier(values=_values(expected))
    copied = copy.copy(original)
    assert type(copied) is type(original) and copied is not original
    with pytest.raises(ValueError, match=_INVALID):
        copied.descriptor()
    assert original.descriptor() == expected


@pytest.mark.parametrize("method", ["__init__", "descriptor", "prepare"])
def test_foreign_self_is_rejected_without_reading_attributes(method):
    reads = []

    class Foreign:
        def __getattribute__(self, name):
            reads.append(name)
            raise AssertionError("foreign self fields were read")

        def __setattr__(self, name, value):
            reads.append(name)
            raise AssertionError("foreign self received a Runtime or state field")

    operation = getattr(preparation._InitialSelectionPreparation, method)
    with pytest.raises(ValueError, match=_INVALID):
        if method == "__init__":
            operation(Foreign(), object())
        elif method == "prepare":
            operation(Foreign(), deadline_ns=_MAX_NS)
        else:
            operation(Foreign())
    assert reads == []


@pytest.mark.parametrize("method", ["descriptor", "prepare"])
def test_public_entries_reject_wrong_thread_before_borrowing_runtime(method):
    expected = _descriptor()
    owner = _getter_carrier(values=_values(expected))
    outcomes = []

    def other_thread():
        try:
            if method == "prepare":
                owner.prepare(deadline_ns=_MAX_NS)
            else:
                owner.descriptor()
        except BaseException as error:
            outcomes.append(error)

    caller = threading.Thread(target=other_thread)
    try:
        caller.start()
    finally:
        if caller.ident is not None:
            caller.join(3)
    assert not caller.is_alive()
    assert len(outcomes) == 1 and type(outcomes[0]) is ValueError
    assert str(outcomes[0]) == "INITIAL_SELECTION_PREPARATION_INVALID"
    assert owner.descriptor() == expected


def test_reinitialization_cannot_reset_an_existing_native_state_or_borrow_runtime():
    expected = _descriptor()
    baseline = _values(expected)
    owner = _getter_carrier(values=baseline)
    before = vars(owner).copy()
    reads = []

    class UnreadableRuntime:
        def __getattribute__(self, name):
            reads.append(name)
            raise AssertionError("reinitialization inspected a new Runtime")

    with pytest.raises(ValueError, match=_INVALID):
        preparation._InitialSelectionPreparation.__init__(owner, UnreadableRuntime())
    assert vars(owner) == before
    assert owner._attempted is True and owner._descriptor_values is baseline
    assert owner.descriptor() == expected
    assert reads == []


_OWN_METHODS = ("__init__", "prepare", "descriptor", "_identity", "_check", "_refresh", "_verify")


@pytest.mark.parametrize("method", _OWN_METHODS)
@pytest.mark.parametrize("placement", ["class", "instance"])
def test_own_workflow_substitution_cannot_replace_saved_getter_entry(
    monkeypatch, method, placement
):
    expected = _descriptor()
    owner = _getter_carrier(values=_values(expected))
    original_entry = preparation._InitialSelectionPreparation.descriptor
    assert tuple(name for name, _ in preparation._OWN_METHODS) == _OWN_METHODS
    assert original_entry(owner) == expected
    calls = []

    def replacement(*args, **kwargs):
        calls.append("substitute")
        raise AssertionError("a changed adapter workflow method ran")

    with monkeypatch.context() as local:
        if placement == "class":
            local.setattr(preparation._InitialSelectionPreparation, method, replacement)
        else:
            local.setitem(vars(owner), method, replacement)
        # Invoke the saved public entry. Calling a replaced public function is
        # not intercepted or claimed safe by this finite cooperating-process gate.
        with pytest.raises(ValueError, match=_INVALID):
            original_entry(owner)
    assert calls == []
    assert original_entry(owner) == expected


@pytest.mark.parametrize("missing", ["_instance", "_thread", "_attempted", "_descriptor_values"])
def test_missing_native_identity_state_fails_with_fixed_error_before_runtime_access(missing):
    value = _getter_carrier(values=_values(_descriptor()))
    del vars(value)[missing]
    with pytest.raises(ValueError, match=_INVALID):
        value.descriptor()


def test_adapter_module_class_replacement_denies_through_saved_entry(monkeypatch):
    expected = _descriptor()
    value = _getter_carrier(values=_values(expected))
    original_entry = preparation._InitialSelectionPreparation.descriptor
    assert original_entry(value) == expected
    calls = []

    def replacement(*args, **kwargs):
        calls.append("replacement")
        raise AssertionError("replacement adapter class was called")

    monkeypatch.setattr(preparation, "_InitialSelectionPreparation", replacement)
    with pytest.raises(ValueError, match=_INVALID):
        original_entry(value)
    assert calls == []


@pytest.mark.parametrize(
    "binding",
    [
        "InitialSelectionDescriptor",
        "__post_init__",
        "_descriptor_values",
        "_validated_values",
        "_from_values",
    ],
)
def test_getter_descriptor_binding_drift_never_invokes_the_substitute(monkeypatch, binding):
    expected = _descriptor()
    value = _getter_carrier(values=_values(expected))
    assert value.descriptor() == expected
    calls = []

    def replacement(*args, **kwargs):
        calls.append("replacement")
        raise AssertionError("changed descriptor operation ran")

    with monkeypatch.context() as local:
        target = (
            InitialSelectionDescriptor if binding == "__post_init__" else preparation.descriptors
        )
        local.setattr(target, binding, replacement)
        with pytest.raises(ValueError, match=_INVALID):
            value.descriptor()
    assert calls == []
    assert value.descriptor() == expected


@pytest.mark.parametrize(
    "binding",
    [
        "_default_synthetic_initial_assignment",
        "_DEFAULT_SYNTHETIC_INITIAL_ASSIGNMENT",
        "selection_digest",
        "local_digest",
    ],
)
def test_pure_helper_binding_check_denies_changed_builder_or_digest_without_calling_it(
    monkeypatch, binding
):
    calls = []

    def replacement(*args, **kwargs):
        calls.append("replacement")
        raise AssertionError("changed pure operation ran")

    assert preparation._pure_bindings() is None
    with monkeypatch.context() as local:
        if binding == "local_digest":
            local.setattr(preparation, "content_digest", replacement)
        elif binding == "selection_digest":
            local.setattr(preparation.selection, "content_digest", replacement)
        else:
            local.setattr(preparation.selection, binding, replacement)
        with pytest.raises(ValueError, match=_INVALID):
            preparation._pure_bindings()
    assert calls == []
    assert preparation._pure_bindings() is None


def _method_carrier():
    """Exact-class carriers for the PURE method-identity checker only.

    These do not have initialized owner state, leases, Engines, artifacts or SQL.
    Never pass them to adapter construction/prepare or a Runtime method. The
    successful assertion below means only unchanged method identities.
    """
    runtime = object.__new__(preparation._RUNTIME)
    reader = object.__new__(preparation.SqlContinuousIntegrityReader)
    account = object.__new__(preparation.SqlContinuousAccount)
    daily = object.__new__(preparation.SqlDailyRuntimeRisk)
    producer = object.__new__(preparation.SqlContinuousRuntimeSources)
    dependencies = object.__new__(preparation.SqlRuntimeOwnerDependencies)
    associations = object.__new__(preparation.SqlRuntimeOwnerAssociations)
    publisher = object.__new__(preparation.SqlContinuousReconciliationPublication)
    runtime._instance = runtime
    runtime._thread = threading.current_thread()
    runtime.reader = reader
    reader.account = account
    reader.daily = daily
    reader.associations = associations
    reader.publisher = publisher
    daily.producers = producer
    producer.owner_dependencies = dependencies
    return SimpleNamespace(runtime=runtime, account=account, daily=daily, dependencies=dependencies)


_DIRECT_METHODS = (
    ("runtime", "_require"),
    ("runtime", "_now"),
    ("runtime", "_lease_deadline"),
    ("runtime", "_before"),
    ("runtime", "verify"),
    ("account", "restore"),
    ("account", "require_resolved"),
    ("daily", "read_snapshot"),
    ("daily", "resolve_snapshot"),
    ("daily", "require_resolved_snapshot"),
    ("dependencies", "_bound"),
    ("dependencies", "prepare_dependencies"),
    ("dependencies", "require_prepared"),
)


@pytest.mark.parametrize("owner_name,method", _DIRECT_METHODS)
@pytest.mark.parametrize("placement", ["class", "instance"])
def test_each_direct_method_pin_denies_before_substitute_invocation(
    monkeypatch, owner_name, method, placement
):
    carrier = _method_carrier()
    calls = []

    def replacement(*args, **kwargs):
        calls.append("substitute")
        raise AssertionError("a changed direct owner method was invoked")

    # Exercise the actual pure checker in both directions, not a financial
    # admission. No original or replacement owner method is invoked here.
    assert preparation._direct_bindings(carrier.runtime) is None
    owner = getattr(carrier, owner_name)
    with monkeypatch.context() as local:
        if placement == "class":
            local.setattr(type(owner), method, replacement)
        else:
            # Restore exact absence, rather than storing a bound method shadow
            # while pytest undoes an instance setattr.
            local.setitem(vars(owner), method, replacement)
        with pytest.raises(ValueError, match=_INVALID):
            preparation._direct_bindings(carrier.runtime)
    assert calls == []
    assert preparation._direct_bindings(carrier.runtime) is None


@pytest.mark.parametrize("assignment", [None, "d" * 64])
def test_fingerprint_helper_returns_only_original_native_immutable_shape(assignment):
    value = ("a" * 64, "b" * 64, "c" * 64, assignment, ("e" * 64, "f" * 64, "0" * 64))
    result = preparation._fingerprint(value)
    assert type(result) is tuple and type(result[4]) is tuple
    assert result == value


@pytest.mark.parametrize("kind", ["list", "short", "nested-list", "digest", "subclass"])
def test_fingerprint_helper_rejects_bad_native_shape_without_user_operators(kind):
    calls = []

    class HostileText(str):
        def __len__(self):
            calls.append("len")
            raise AssertionError("fingerprint invoked a non-native string")

        def __eq__(self, other):
            calls.append("eq")
            raise AssertionError("fingerprint invoked a non-native string")

    valid = ("a" * 64, "b" * 64, "c" * 64, None, ("e" * 64, "f" * 64, "0" * 64))
    value = {
        "list": list(valid),
        "short": valid[:4],
        "nested-list": (*valid[:4], list(valid[4])),
        "digest": ("not-a-digest", *valid[1:]),
        "subclass": (HostileText("a" * 64), *valid[1:]),
    }[kind]
    with pytest.raises(ValueError, match=_INVALID):
        preparation._fingerprint(value)
    assert calls == []
