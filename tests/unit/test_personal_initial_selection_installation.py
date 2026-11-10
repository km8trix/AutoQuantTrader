"""Native locator and historical-state boundaries, never an installation model.

No G/E graph, full proof, REQUEST retention, publication or financial success is
fabricated here. Genuine fresh SQL fixtures separately qualify those effects.
"""

import builtins
import copy
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from sqlalchemy import Engine

from apps.trader import initial_selection_installation as installation
from packages.domain.durable_journal_contracts import MAX_SEQUENCE, JournalHead, JournalReceipt

_INVALID = "^INITIAL_SELECTION_INSTALLATION_INVALID$"
_MAX_NS = 2**63 - 1


def _receipt():
    return JournalReceipt(
        command_id="native-install-request",
        command_sha256="d" * 64,
        append_sha256="e" * 64,
        previous_head=JournalHead("a" * 64, 7, "b" * 64),
        committed_head=JournalHead("a" * 64, 8, "c" * 64),
        record_ids=("native-install-request",),
        record_hashes=("f" * 64,),
    )


def _receipt_fields(value):
    return (
        value.command_id,
        value.command_sha256,
        value.append_sha256,
        value.previous_head.key_sha256,
        value.previous_head.sequence,
        value.previous_head.entry_sha256,
        value.committed_head.key_sha256,
        value.committed_head.sequence,
        value.committed_head.entry_sha256,
        value.record_ids,
        value.record_hashes,
    )


@pytest.mark.parametrize(
    ("attempted", "started", "returned", "request_sha", "assignment"),
    [
        (False, False, False, None, None),
        (True, False, False, "a" * 64, None),
        (True, True, False, "a" * 64, None),
        (True, True, True, "a" * 64, None),
        (True, True, True, "a" * 64, "b" * 64),
    ],
)
def test_observation_represents_only_the_five_permitted_native_fact_shapes(
    attempted, started, returned, request_sha, assignment
):
    value = installation.InitialSelectionInstallationObservation(
        attempted=attempted,
        publication_started=started,
        publication_returned=returned,
        request_receipt_sha256=request_sha,
        assignment_sha256=assignment,
    )
    assert value.attempted is attempted
    assert value.publication_started is started
    assert value.publication_returned is returned
    assert value.request_receipt_sha256 == request_sha
    assert value.assignment_sha256 == assignment
    assert all(
        type(flag) is bool
        for flag in (
            value.attempted,
            value.publication_started,
            value.publication_returned,
        )
    )
    with pytest.raises(FrozenInstanceError):
        value.attempted = False


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("attempted", 1),
        ("attempted", None),
        ("publication_started", 0),
        ("publication_started", "true"),
        ("publication_returned", 1),
        ("publication_returned", object()),
        ("request_receipt_sha256", "A" * 64),
        ("request_receipt_sha256", "0" * 63),
        ("request_receipt_sha256", b"0" * 64),
        ("assignment_sha256", "not-a-digest"),
        ("assignment_sha256", True),
    ],
)
def test_observation_rejects_non_native_flags_and_malformed_digest_data(field, bad):
    arguments = dict(
        attempted=True,
        publication_started=True,
        publication_returned=True,
        request_receipt_sha256="a" * 64,
        assignment_sha256="b" * 64,
    )
    arguments[field] = bad
    with pytest.raises(ValueError, match=_INVALID):
        installation.InitialSelectionInstallationObservation(**arguments)


@pytest.mark.parametrize(
    ("attempted", "started", "returned", "request_sha", "assignment"),
    [
        (False, True, False, None, None),
        (False, False, True, None, None),
        (False, False, False, "a" * 64, None),
        (True, False, False, None, None),
        (True, False, True, "a" * 64, None),
        (True, False, False, "a" * 64, "b" * 64),
        (True, True, False, "a" * 64, "b" * 64),
    ],
)
def test_observation_cannot_promote_unknown_or_unattempted_state_to_returned_facts(
    attempted, started, returned, request_sha, assignment
):
    with pytest.raises(ValueError, match=_INVALID):
        installation.InitialSelectionInstallationObservation(
            attempted=attempted,
            publication_started=started,
            publication_returned=returned,
            request_receipt_sha256=request_sha,
            assignment_sha256=assignment,
        )


def test_receipt_snapshot_uses_the_exact_eleven_distinct_native_components():
    original = _receipt()
    expected = (
        "native-install-request",
        "d" * 64,
        "e" * 64,
        "a" * 64,
        7,
        "b" * 64,
        "a" * 64,
        8,
        "c" * 64,
        ("native-install-request",),
        ("f" * 64,),
    )
    values = installation._receipt_values(original)
    assert type(values) is tuple and values == expected
    first = installation._receipt_from_values(values)
    second = installation._receipt_from_values(values)
    assert type(first) is type(second) is JournalReceipt
    assert first == second == original
    assert first is not second and first is not original
    assert first.previous_head is not original.previous_head
    assert first.committed_head is not second.committed_head
    assert _receipt_fields(first) == expected
    object.__setattr__(original, "command_id", "caller-mutated")
    object.__setattr__(original.previous_head, "sequence", 100)
    object.__setattr__(first.committed_head, "entry_sha256", "0" * 64)
    third = installation._receipt_from_values(values)
    assert _receipt_fields(third) == _receipt_fields(second) == expected
    assert values == expected


def test_receipt_keeps_original_unicode_identifier_admission_without_ascii_restriction():
    identifier = "請求-" + "é" * 125
    assert len(identifier) == 128 and len(identifier.encode("utf-8")) > 128
    original = _receipt()
    object.__setattr__(original, "command_id", identifier)
    object.__setattr__(original, "record_ids", (identifier,))
    original.__post_init__()
    values = installation._receipt_values(original)
    assert values[0] == identifier and values[9] == (identifier,)
    assert installation._receipt_from_values(values) == original


@pytest.mark.parametrize("before", [0, MAX_SEQUENCE - 1])
def test_receipt_preserves_original_inclusive_head_counter_bounds(before):
    original = _receipt()
    object.__setattr__(original.previous_head, "sequence", before)
    object.__setattr__(original.committed_head, "sequence", before + 1)
    original.previous_head.__post_init__()
    original.committed_head.__post_init__()
    original.__post_init__()
    values = installation._receipt_values(original)
    assert values[4] == before and values[7] == before + 1
    assert installation._receipt_from_values(values) == original


def test_receipt_snapshot_does_not_reread_caller_fields_after_original_validation_begins():
    caller = _receipt()
    expected = _receipt_fields(caller)
    original_profile = sys.getprofile()
    original_code = JournalHead.__post_init__.__code__
    observations = []

    def profile(frame, event, argument):
        if event == "call" and frame.f_code is original_code and not observations:
            observations.append(frame.f_locals["self"])
            object.__setattr__(caller, "command_id", "changed-during-validation")
            object.__setattr__(caller, "command_sha256", "0" * 64)
            object.__setattr__(caller, "append_sha256", "1" * 64)
            object.__setattr__(caller.previous_head, "sequence", 20)
            object.__setattr__(caller.committed_head, "sequence", 21)
            object.__setattr__(caller, "record_ids", ("changed-during-validation",))
            object.__setattr__(caller, "record_hashes", ("2" * 64,))

    try:
        sys.setprofile(profile)
        values = installation._receipt_values(caller)
    finally:
        sys.setprofile(original_profile)
    assert sys.getprofile() is original_profile
    assert len(observations) == 1 and observations[0] is not caller.previous_head
    assert values == expected
    assert _receipt_fields(installation._receipt_from_values(values)) == expected
    assert caller.command_id == "changed-during-validation"


@pytest.mark.parametrize("kind", ["counter", "digest", "ids", "late-hash"])
def test_all_native_receipt_leaves_are_admitted_before_original_callbacks(kind):
    callbacks = []

    def forbidden(*args, **kwargs):
        callbacks.append("operator")
        raise AssertionError("receipt native admission invoked a user operator")

    class HostileInt(int):
        __add__ = forbidden
        __lt__ = forbidden
        __le__ = forbidden
        __eq__ = forbidden
        __hash__ = forbidden

    class HostileText(str):
        __len__ = forbidden
        __iter__ = forbidden
        __eq__ = forbidden
        __hash__ = forbidden

    class HostileTuple(tuple):
        __len__ = forbidden
        __iter__ = forbidden
        __getitem__ = forbidden

    caller = _receipt()
    if kind == "counter":
        object.__setattr__(caller.previous_head, "sequence", HostileInt(7))
    elif kind == "digest":
        object.__setattr__(caller, "command_sha256", HostileText("d" * 64))
    elif kind == "ids":
        object.__setattr__(caller, "record_ids", HostileTuple(("native-install-request",)))
    else:
        object.__setattr__(caller, "record_hashes", (HostileText("f" * 64),))
    original_codes = (
        JournalHead.__init__.__code__,
        JournalHead.__post_init__.__code__,
        JournalReceipt.__init__.__code__,
        JournalReceipt.__post_init__.__code__,
    )
    original_profile = sys.getprofile()
    validations = []

    def profile(frame, event, argument):
        if event == "call" and any(frame.f_code is code for code in original_codes):
            validations.append(frame.f_code)

    try:
        sys.setprofile(profile)
        with pytest.raises(ValueError, match=_INVALID):
            installation._receipt_values(caller)
    finally:
        sys.setprofile(original_profile)
    assert sys.getprofile() is original_profile
    assert callbacks == validations == []


@pytest.mark.parametrize(
    "kind",
    [
        "not-receipt",
        "previous-head",
        "committed-head",
        "bool-counter",
        "negative-counter",
        "counter-overflow",
        "head-key",
        "head-gap",
        "command-id",
        "command-hash",
        "append-hash",
        "empty-records",
        "two-records",
        "over-original-inventory",
        "wrong-record-id",
        "wrong-record-hash",
        "mismatched-inventory",
        "list-hashes",
    ],
)
def test_native_receipt_requires_original_bounds_and_exact_one_request_record(kind):
    caller = _receipt()
    if kind == "not-receipt":
        caller = object()
    elif kind == "previous-head":
        object.__setattr__(caller, "previous_head", object())
    elif kind == "committed-head":
        object.__setattr__(caller, "committed_head", object())
    elif kind == "bool-counter":
        object.__setattr__(caller.previous_head, "sequence", True)
    elif kind == "negative-counter":
        object.__setattr__(caller.previous_head, "sequence", -1)
    elif kind == "counter-overflow":
        object.__setattr__(caller.committed_head, "sequence", _MAX_NS + 1)
    elif kind == "head-key":
        object.__setattr__(caller.committed_head, "key_sha256", "0" * 64)
    elif kind == "head-gap":
        object.__setattr__(caller.committed_head, "sequence", 9)
    elif kind == "command-id":
        object.__setattr__(caller, "command_id", " padded ")
    elif kind == "command-hash":
        object.__setattr__(caller, "command_sha256", "D" * 64)
    elif kind == "append-hash":
        object.__setattr__(caller, "append_sha256", "e" * 63)
    elif kind == "empty-records":
        object.__setattr__(caller, "record_ids", ())
        object.__setattr__(caller, "record_hashes", ())
    elif kind == "two-records":
        object.__setattr__(caller, "record_ids", ("native-install-request", "second"))
        object.__setattr__(caller, "record_hashes", ("f" * 64, "0" * 64))
        object.__setattr__(caller.committed_head, "sequence", 9)
    elif kind == "over-original-inventory":
        object.__setattr__(caller, "record_ids", tuple("id" + str(i) for i in range(65)))
        object.__setattr__(caller, "record_hashes", ("f" * 64,) * 65)
        object.__setattr__(caller.committed_head, "sequence", 72)
    elif kind == "wrong-record-id":
        object.__setattr__(caller, "record_ids", ("another-request",))
    elif kind == "wrong-record-hash":
        object.__setattr__(caller, "record_hashes", ("invalid",))
    elif kind == "mismatched-inventory":
        object.__setattr__(caller, "record_hashes", ())
    else:
        object.__setattr__(caller, "record_hashes", ["f" * 64])
    with pytest.raises(ValueError, match=_INVALID):
        installation._receipt_values(caller)


@pytest.mark.parametrize("value", [1, _MAX_NS])
def test_native_deadline_retains_original_positive_integer_boundary(value):
    assert installation._deadline(value) == value
    assert type(installation._deadline(value)) is int


@pytest.mark.parametrize("value", [None, False, True, 0, -1, 1.0, "1", _MAX_NS + 1])
def test_native_deadline_rejects_without_coercion(value):
    with pytest.raises(ValueError, match=_INVALID):
        installation._deadline(value)


def test_deadline_subclass_cannot_invoke_operators_or_coercion():
    callbacks = []

    def forbidden(*args, **kwargs):
        callbacks.append("operator")
        raise AssertionError("deadline boundary invoked a non-native integer")

    class HostileInt(int):
        __lt__ = forbidden
        __le__ = forbidden
        __gt__ = forbidden
        __ge__ = forbidden
        __int__ = forbidden
        __index__ = forbidden

    with pytest.raises(ValueError, match=_INVALID):
        installation._deadline(HostileInt(1))
    assert callbacks == []


def _historical_carrier(values=(False, False, False, None, None)):
    """Only historical native metadata, not a constructed/eligible installer."""
    owner = object.__new__(installation._InitialSelectionInstallation)
    owner._instance = owner
    owner._thread = threading.current_thread()
    owner._observation = values
    return owner


def test_historical_observation_uses_only_three_native_fields_and_no_live_resources(monkeypatch):
    baseline = (True, True, True, "a" * 64, "b" * 64)
    owner = _historical_carrier(baseline)
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("historical observation reached live work")

    # Deliberately no preparation/runtime/graph fields exist. This is a pure
    # getter carrier; it does not qualify preparation or actual installation.
    assert set(vars(owner)) == {"_instance", "_thread", "_observation"}
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
            (threading.Thread, "start"),
            (time, "time"),
            (time, "monotonic"),
            (time, "monotonic_ns"),
        ):
            local.setattr(target, name, forbidden)
        first, second = owner.observation(), owner.observation()
    assert first is not second and first == second
    assert (
        first.attempted,
        first.publication_started,
        first.publication_returned,
        first.request_receipt_sha256,
        first.assignment_sha256,
    ) == baseline
    object.__setattr__(first, "publication_returned", False)
    object.__setattr__(first, "assignment_sha256", "0" * 64)
    third = owner.observation()
    assert third == second and third is not second
    assert owner._observation is baseline and effects == []


@pytest.mark.parametrize("method", ["__init__", "install", "observation"])
def test_foreign_receiver_is_rejected_before_borrowing_fields_or_request(method):
    callbacks = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign receiver fields were borrowed")

        def __setattr__(self, name, value):
            callbacks.append(name)
            raise AssertionError("foreign receiver received installer state")

    operation = getattr(installation._InitialSelectionInstallation, method)
    with pytest.raises(ValueError, match=_INVALID):
        if method == "__init__":
            operation(Foreign(), Foreign())
        elif method == "install":
            operation(Foreign(), Foreign(), deadline_ns=_MAX_NS)
        else:
            operation(Foreign())
    assert callbacks == []


def test_reinitialization_cannot_reset_existing_historical_state_or_borrow_preparation():
    baseline = (True, True, False, "a" * 64, None)
    owner = _historical_carrier(baseline)
    before = vars(owner).copy()
    callbacks = []

    class Unreadable:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("reinitialization borrowed a preparation")

    with pytest.raises(ValueError, match=_INVALID):
        owner.__init__(Unreadable())
    assert vars(owner) == before and owner._observation is baseline
    assert owner.observation().publication_started is True
    assert callbacks == []


def test_copied_receiver_cannot_export_original_historical_observation():
    original = _historical_carrier((True, True, False, "a" * 64, None))
    expected = original.observation()
    copied = copy.copy(original)
    assert copied is not original and type(copied) is type(original)
    with pytest.raises(ValueError, match=_INVALID):
        copied.observation()
    assert original.observation() == expected


@pytest.mark.parametrize("missing", ["_instance", "_thread", "_observation"])
def test_missing_native_historical_identity_has_fixed_failure(missing):
    owner = _historical_carrier()
    del vars(owner)[missing]
    with pytest.raises(ValueError, match=_INVALID):
        owner.observation()


def test_historical_observation_still_rejects_a_foreign_thread_without_poisoning_owner():
    owner = _historical_carrier((True, True, True, "a" * 64, None))
    expected = owner.observation()
    outcomes = []

    def call():
        try:
            outcomes.append(owner.observation())
        except BaseException as error:
            outcomes.append(error)

    thread = threading.Thread(target=call)
    try:
        thread.start()
        thread.join(2)
    finally:
        if thread.ident is not None:
            thread.join(2)
    assert not thread.is_alive() and len(outcomes) == 1
    assert (
        type(outcomes[0]) is ValueError
        and str(outcomes[0]) == "INITIAL_SELECTION_INSTALLATION_INVALID"
    )
    assert owner.observation() == expected


@pytest.mark.parametrize("bad", [None, [], (1, False, False, None, None), (False, False)])
def test_corrupt_historical_observation_is_not_repaired_or_promoted(bad):
    owner = _historical_carrier(bad)
    with pytest.raises(ValueError, match=_INVALID):
        owner.observation()
    assert owner._observation is bad


def test_foreign_preparation_is_denied_before_any_field_or_runtime_loan():
    callbacks = []

    class ForeignPreparation:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign preparation attributes were borrowed")

    with pytest.raises(ValueError, match=_INVALID):
        installation._InitialSelectionInstallation(ForeignPreparation())
    assert callbacks == []


@pytest.mark.parametrize("method", ["__init__", "install", "observation", "_check", "_refresh"])
@pytest.mark.parametrize("placement", ["class", "instance"])
def test_saved_observation_entry_denies_finite_method_substitution_without_calling_it(
    monkeypatch, method, placement
):
    owner = _historical_carrier((True, True, False, "a" * 64, None))
    original_entry = installation._InitialSelectionInstallation.observation
    expected = original_entry(owner)
    callbacks = []

    def replacement(*args, **kwargs):
        callbacks.append("substitute")
        raise AssertionError("changed installation method ran")

    with monkeypatch.context() as local:
        if placement == "class":
            local.setattr(type(owner), method, replacement)
        else:
            local.setitem(vars(owner), method, replacement)
        with pytest.raises(ValueError, match=_INVALID):
            original_entry(owner)
    assert callbacks == []
    assert original_entry(owner) == expected


def test_late_invalid_receipt_tuple_hash_runs_no_original_constructor_or_user_operator():
    callbacks = []

    class HostileText(str):
        def __len__(self):
            callbacks.append("len")
            raise AssertionError("private tuple consumer measured a non-native leaf")

        def __eq__(self, other):
            callbacks.append("eq")
            raise AssertionError("private tuple consumer compared a non-native leaf")

    valid = installation._receipt_values(_receipt())
    invalid = (*valid[:10], (HostileText("f" * 64),))
    original_profile = sys.getprofile()
    original_codes = (JournalHead.__init__.__code__, JournalReceipt.__init__.__code__)
    constructors = []

    def profile(frame, event, argument):
        if event == "call" and any(frame.f_code is code for code in original_codes):
            constructors.append(frame.f_code)

    try:
        sys.setprofile(profile)
        with pytest.raises(ValueError, match=_INVALID):
            installation._receipt_from_values(invalid)
    finally:
        sys.setprofile(original_profile)
    assert sys.getprofile() is original_profile
    assert callbacks == constructors == []


def test_retained_partial_preparation_without_descriptor_is_ineligible_before_live_checks():
    # Exact-class negative carrier only: it has no genuine preparation, Runtime
    # or dependency ownership. Presence of an incomplete prepared-shaped value
    # must never turn a failed E attempt into eligible installation authority.
    preparation = object.__new__(installation._PREPARATION)
    preparation._instance = preparation
    preparation._thread = threading.current_thread()
    preparation._attempted = True
    preparation._descriptor_values = None
    preparation._prepared = object.__new__(installation.PreparedRuntimeOwnerDependencies)
    callbacks = []

    class UnreadableRuntime:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("failed preparation loaned its Runtime")

    preparation._runtime = UnreadableRuntime()
    with pytest.raises(ValueError, match=_INVALID):
        installation._InitialSelectionInstallation(preparation)
    assert callbacks == []
    assert preparation._descriptor_values is None


@pytest.mark.parametrize(
    "binding",
    [
        "head-class",
        "receipt-class",
        "head-init",
        "head-validate",
        "receipt-init",
        "receipt-validate",
    ],
)
def test_receipt_constructor_and_validator_binding_drift_denies_before_substitution(
    monkeypatch, binding
):
    original = _receipt()
    callbacks = []

    def replacement(*args, **kwargs):
        callbacks.append("substitute")
        raise AssertionError("changed receipt constructor or validator ran")

    targets = {
        "head-class": (installation.journal_values, "JournalHead"),
        "receipt-class": (installation.journal_values, "JournalReceipt"),
        "head-init": (JournalHead, "__init__"),
        "head-validate": (JournalHead, "__post_init__"),
        "receipt-init": (JournalReceipt, "__init__"),
        "receipt-validate": (JournalReceipt, "__post_init__"),
    }
    with monkeypatch.context() as local:
        target, name = targets[binding]
        local.setattr(target, name, replacement)
        with pytest.raises(ValueError, match=_INVALID):
            installation._receipt_values(original)
    assert callbacks == []
    assert installation._receipt_from_values(installation._receipt_values(original)) == original


@pytest.mark.parametrize("binding", ["class", "init", "validate"])
def test_observation_copy_checks_original_dto_bindings_before_any_replacement(monkeypatch, binding):
    baseline = (True, True, True, "a" * 64, None)
    expected = installation._observation_from_values(baseline)
    callbacks = []

    def replacement(*args, **kwargs):
        callbacks.append("substitute")
        raise AssertionError("changed observation constructor or validator ran")

    with monkeypatch.context() as local:
        if binding == "class":
            local.setattr(installation, "InitialSelectionInstallationObservation", replacement)
        else:
            name = "__init__" if binding == "init" else "__post_init__"
            local.setattr(installation.InitialSelectionInstallationObservation, name, replacement)
        with pytest.raises(ValueError, match=_INVALID):
            installation._observation_from_values(baseline)
    assert callbacks == []
    assert installation._observation_from_values(baseline) == expected
