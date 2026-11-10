"""Native installation delivery only, never modeled financial success.

Literal observations and manually staged Condition state qualify copying,
admission and acknowledgement boundaries only. No G/E graph, proof, retained
REQUEST, installation, lease release or successful resource cleanup is invented.
The separate genuine integrations own those claims.
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
from apps.trader import initial_selection_preparation_owner as host
from apps.trader.initial_selection_installation import InitialSelectionInstallationObservation
from packages.domain.durable_journal_contracts import JournalHead, JournalReceipt

_ARGUMENT = "^INITIAL_SELECTION_PREPARATION_OWNER_ARGUMENT_INVALID$"
_STATE = "^INITIAL_SELECTION_PREPARATION_OWNER_STATE_INVALID$"
_BINDING = "^INITIAL_SELECTION_PREPARATION_OWNER_BINDING_CHANGED$"
_MAX_NS = 2**63 - 1
_UNAVAILABLE = (
    "not_started",
    "starting",
    "busy",
    "reentrant",
    "preparation_unavailable",
    "already_attempted",
    "cancelled",
    "deadline",
    "stopping",
    "stopped",
    "clock_invalid",
    "installation_failed",
    "cleanup_failed",
)
_PREPARATION_METHODS = (
    "__init__",
    "start",
    "status",
    "stop",
    "prepare_initial_selection",
    "_snapshot",
    "_latch",
    "_now",
    "_serve",
    "_run",
)


def _owner():
    return host.InitialSelectionPreparationOwner(
        configuration_path="/private/tmp/installation-native/configuration.json",
        account_id="native-installation-account",
        instance_lock="/private/tmp/installation-native/instance.lock",
    )


def _receipt():
    return JournalReceipt(
        command_id="native-install-request",
        command_sha256="1" * 64,
        append_sha256="2" * 64,
        previous_head=JournalHead("3" * 64, 7, "4" * 64),
        committed_head=JournalHead("3" * 64, 8, "5" * 64),
        record_ids=("native-install-request",),
        record_hashes=("6" * 64,),
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


def _facts():
    # Literal native metadata only, with no claim that original G produced it.
    return InitialSelectionInstallationObservation(
        attempted=True,
        publication_started=True,
        publication_returned=True,
        request_receipt_sha256="a" * 64,
        assignment_sha256="b" * 64,
    )


def _result_arguments():
    return dict(
        status="installed",
        reason="installed",
        call_id="native-install-call",
        incarnation="native-install-incarnation",
        observation=_facts(),
    )


def test_installed_result_contains_only_exact_native_metadata_and_is_frozen():
    value = host.InitialSelectionInstallationResult(**_result_arguments())
    assert (value.status, value.reason, value.call_id, value.incarnation) == (
        "installed",
        "installed",
        "native-install-call",
        "native-install-incarnation",
    )
    assert type(value.observation) is InitialSelectionInstallationObservation
    assert (
        value.observation.attempted,
        value.observation.publication_started,
        value.observation.publication_returned,
        value.observation.request_receipt_sha256,
        value.observation.assignment_sha256,
    ) == (True, True, True, "a" * 64, "b" * 64)
    assert set(value.__slots__) == {"status", "reason", "call_id", "incarnation", "observation"}
    with pytest.raises(FrozenInstanceError):
        value.reason = "cancelled"


@pytest.mark.parametrize("reason", _UNAVAILABLE)
def test_every_unavailable_reason_contains_no_observation_or_private_graph(reason):
    value = host.InitialSelectionInstallationResult(
        "unavailable", reason, "native-call", "native-incarnation", None
    )
    assert (value.status, value.reason, value.observation) == ("unavailable", reason, None)
    assert set(value.__slots__) == {"status", "reason", "call_id", "incarnation", "observation"}


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("status", True),
        ("status", "ready"),
        ("status", "unavailable"),
        ("reason", True),
        ("reason", "verified"),
        ("reason", "cancelled"),
        ("call_id", ""),
        ("call_id", "a" * 129),
        ("call_id", "call/foreign"),
        ("call_id", True),
        ("incarnation", ""),
        ("incarnation", "a" * 129),
        ("incarnation", "incarnation/foreign"),
        ("incarnation", None),
        ("observation", None),
        ("observation", object()),
    ],
)
def test_installed_result_rejects_native_or_cross_protocol_confusion(name, bad):
    arguments = _result_arguments()
    arguments[name] = bad
    with pytest.raises(ValueError, match=_ARGUMENT):
        host.InitialSelectionInstallationResult(**arguments)


@pytest.mark.parametrize(
    "facts",
    [
        (False, False, False, None, None),
        (True, False, False, "a" * 64, None),
        (True, True, False, "a" * 64, None),
        (True, True, True, "a" * 64, None),
    ],
)
def test_valid_partial_g_facts_cannot_be_promoted_to_installed_delivery(facts):
    observation = InitialSelectionInstallationObservation(
        attempted=facts[0],
        publication_started=facts[1],
        publication_returned=facts[2],
        request_receipt_sha256=facts[3],
        assignment_sha256=facts[4],
    )
    arguments = _result_arguments()
    arguments["observation"] = observation
    with pytest.raises(ValueError, match=_ARGUMENT):
        host.InitialSelectionInstallationResult(**arguments)


def test_unavailable_result_cannot_leak_even_a_valid_full_g_observation():
    with pytest.raises(ValueError, match=_ARGUMENT):
        host.InitialSelectionInstallationResult(
            "unavailable", "cancelled", "native-call", "native-incarnation", _facts()
        )


def test_result_validation_never_coerces_hostile_text_or_observation_subclasses():
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("operator")
        raise AssertionError("installation result coerced a non-native value")

    class HostileText(str):
        __eq__ = forbidden
        __len__ = forbidden
        __hash__ = forbidden

    class HostileObservation(InitialSelectionInstallationObservation):
        def __getattribute__(self, name):
            return forbidden(name)

    for field in ("status", "reason", "call_id", "incarnation"):
        arguments = _result_arguments()
        arguments[field] = HostileText(arguments[field])
        with pytest.raises(ValueError, match=_ARGUMENT):
            host.InitialSelectionInstallationResult(**arguments)
    arguments = _result_arguments()
    arguments["observation"] = object.__new__(HostileObservation)
    with pytest.raises(ValueError, match=_ARGUMENT):
        host.InitialSelectionInstallationResult(**arguments)
    assert calls == []


def test_h_addition_keeps_original_ten_preparation_method_bindings_separate():
    assert tuple(name for name, _ in host._OWN_METHODS) == _PREPARATION_METHODS
    assert "install_initial_selection" not in _PREPARATION_METHODS
    owner = _owner()
    assert owner.status().attempted is False
    assert owner.status().primary_failure is None


def test_data_only_construction_and_result_validation_have_no_live_effects(monkeypatch):
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("native installation metadata reached live I/O")

    with monkeypatch.context() as local:
        for target, name in (
            (builtins, "open"),
            (Path, "open"),
            (Path, "resolve"),
            (Path, "stat"),
            (Path, "lstat"),
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
        owner = _owner()
        status = owner.status()
        result = host.InitialSelectionInstallationResult(**_result_arguments())
    assert effects == [] and owner._thread is None
    assert status.phase == "new" and status.attempted is False
    assert result.observation.assignment_sha256 == "b" * 64


def test_foreign_install_receiver_is_denied_before_any_field_or_receipt_loan():
    calls = []

    class Foreign:
        def __getattribute__(self, name):
            calls.append(name)
            raise AssertionError("foreign installation host fields were borrowed")

    with pytest.raises(ValueError, match=_ARGUMENT):
        host.InitialSelectionPreparationOwner.install_initial_selection(
            Foreign(), "native-call", request_receipt=Foreign()
        )
    assert calls == []


def test_copied_host_cannot_accept_an_installation_request():
    original = _owner()
    copied = copy.copy(original)
    assert copied is not original and copied._instance is original
    with pytest.raises(ValueError, match=_STATE):
        copied.install_initial_selection("native-call", request_receipt=_receipt())
    assert original.status().phase == "new" and original._slot is None


def _idle_transport():
    """Stage admission data only: no worker, E, G or actual completed work."""
    owner = _owner()
    with owner._condition:
        owner._phase, owner._busy, owner._cleanup_ok = "idle", False, False
        owner._startup_deadline = owner._lifetime_deadline = owner._work_deadline = _MAX_NS
        owner._attempted = True
        owner._preparation_return_admitted = True
        owner._prepared_proposal_sha256 = "b" * 64
    return owner


@pytest.mark.parametrize("bad_id", [None, True, "", "a" * 129, "call/foreign"])
def test_bad_install_call_identifier_never_queues_or_samples_clock(monkeypatch, bad_id):
    owner = _idle_transport()
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("bad install identifier reached live work")

    with monkeypatch.context() as local:
        local.setattr(host.time, "monotonic_ns", forbidden)
        local.setattr(Engine, "connect", forbidden)
        with pytest.raises(ValueError, match=_ARGUMENT):
            owner.install_initial_selection(bad_id, request_receipt=_receipt())
    assert effects == [] and owner._slot is owner._active_nonce is None
    assert owner._install_dispatched is False and owner._preparation_return_admitted is True


@pytest.mark.parametrize("kind", ["object", "subclass"])
def test_non_native_cancel_event_is_rejected_before_queue_or_clock(monkeypatch, kind):
    owner = _idle_transport()
    calls = []

    class ForeignEvent(threading.Event):
        def is_set(self):
            calls.append("is_set")
            raise AssertionError("non-native Event callback ran")

    cancel = object() if kind == "object" else ForeignEvent()

    def forbidden(*args, **kwargs):
        calls.append("clock")
        raise AssertionError("bad Event sampled a clock")

    monkeypatch.setattr(host.time, "monotonic_ns", forbidden)
    with pytest.raises(ValueError, match=_ARGUMENT):
        owner.install_initial_selection(
            "native-call", request_receipt=_receipt(), cancel_event=cancel
        )
    assert calls == [] and owner._slot is None and not owner._install_dispatched


@pytest.mark.parametrize(
    ("phase", "busy", "expected"),
    [("new", False, "not_started"), ("starting", True, "starting"), ("stopping", True, "stopping")],
)
def test_host_phase_denial_precedes_unavailable_preparation(phase, busy, expected):
    owner = _owner()
    owner._phase, owner._busy = phase, busy
    owner._preparation_return_admitted = False
    value = owner.install_initial_selection("native-call", request_receipt=_receipt())
    assert (value.status, value.reason, value.observation) == ("unavailable", expected, None)
    assert owner._slot is owner._active_nonce is None and not owner._install_dispatched


def test_busy_shared_slot_precedes_preparation_eligibility_and_never_replaces_request():
    owner = _idle_transport()
    pending = host._Request("same-call", owner._incarnation, _MAX_NS, None)
    owner._slot, owner._active_nonce = pending, pending.nonce
    owner._busy, owner._phase = True, "busy"
    owner._preparation_return_admitted = False
    for correlation in ("same-call", "different-call"):
        value = owner.install_initial_selection(correlation, request_receipt=_receipt())
        assert (value.status, value.reason, value.observation) == ("unavailable", "busy", None)
    assert owner._slot is pending and owner._active_nonce is pending.nonce
    assert not pending.abandoned and not pending.dispatched
    assert not owner._install_dispatched


def test_unadmitted_preparation_is_not_inferred_from_an_attempted_flag():
    owner = _idle_transport()
    owner._preparation_return_admitted = False
    assert owner._attempted is True
    result = owner.install_initial_selection("native-call", request_receipt=_receipt())
    assert (result.status, result.reason, result.observation) == (
        "unavailable",
        "preparation_unavailable",
        None,
    )
    assert owner._slot is owner._active_nonce is None
    assert owner._install_dispatched is False and owner._attempted is True


def test_precancelled_install_preserves_eligibility_and_does_not_consume_dispatch():
    owner = _idle_transport()
    cancel = threading.Event()
    cancel.set()
    result = owner.install_initial_selection(
        "cancelled", request_receipt=_receipt(), cancel_event=cancel
    )
    assert (result.status, result.reason, result.observation) == ("unavailable", "cancelled", None)
    assert owner._slot is owner._active_nonce is None
    assert owner._install_dispatched is False and owner._preparation_return_admitted is True
    assert owner._attempted is True and not owner._stop_event.is_set()


def test_native_event_sampling_ignores_instance_override_without_invoking_it():
    owner = _idle_transport()
    calls = []
    cancel = threading.Event()
    cancel.set()

    def forbidden():
        calls.append("substituted-event")
        raise AssertionError("Event instance method was invoked")

    cancel.is_set = forbidden
    result = owner.install_initial_selection(
        "cancelled", request_receipt=_receipt(), cancel_event=cancel
    )
    assert result.reason == "cancelled" and result.observation is None
    assert calls == [] and owner._slot is None and not owner._install_dispatched


def test_nonboolean_native_event_state_is_denied_without_dispatch():
    owner = _idle_transport()
    cancel = threading.Event()
    cancel._flag = 1
    with pytest.raises(ValueError, match=_STATE):
        owner.install_initial_selection(
            "native-call", request_receipt=_receipt(), cancel_event=cancel
        )
    assert owner._slot is None and owner._install_dispatched is False


def test_terminal_stop_before_start_returns_stopped_without_clock_or_thread(monkeypatch):
    owner = _owner()
    stopped = owner.stop()
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("effect")
        raise AssertionError("stopped install admission reached a live effect")

    with monkeypatch.context() as local:
        local.setattr(host.time, "monotonic_ns", forbidden)
        local.setattr(threading.Thread, "start", forbidden)
        result = owner.install_initial_selection("native-call", request_receipt=_receipt())
    assert stopped.phase == "stopped" and stopped.cleanup_complete
    assert (result.status, result.reason, result.observation) == ("unavailable", "stopped", None)
    assert calls == [] and owner._slot is owner._thread is None and not owner._install_dispatched


def test_owner_thread_reentry_denies_without_waiting_or_queueing(monkeypatch):
    owner = _idle_transport()
    outcomes, waits = [], []

    def forbidden(timeout):
        waits.append(timeout)
        raise AssertionError("owner-thread install attempted to wait")

    def call():
        owner._thread = threading.current_thread()
        try:
            outcomes.append(
                owner.install_initial_selection("reentrant", request_receipt=_receipt())
            )
        except BaseException as error:
            outcomes.append(error)

    caller = threading.Thread(target=call)
    try:
        with monkeypatch.context() as local:
            local.setattr(owner._condition, "wait", forbidden)
            caller.start()
            caller.join(2)
    finally:
        if caller.ident is not None:
            caller.join(2)
    assert not caller.is_alive() and len(outcomes) == 1
    result = outcomes[0]
    assert (result.status, result.reason, result.observation) == ("unavailable", "reentrant", None)
    assert waits == [] and owner._slot is None and not owner._install_dispatched


def test_queued_install_snapshots_receipt_and_abandons_exact_nonce_on_wait_interruption(
    monkeypatch,
):
    owner = _idle_transport()
    caller = _receipt()
    expected = _receipt_fields(caller)
    primary = KeyboardInterrupt("native installation wait interrupted")
    waiting = []

    def interrupt(timeout):
        queued = owner._slot
        waiting.append(queued)
        object.__setattr__(caller, "command_id", "caller-mutated-after-queue")
        object.__setattr__(caller.previous_head, "sequence", 99)
        object.__setattr__(caller, "record_hashes", ("0" * 64,))
        raise primary

    with monkeypatch.context() as local:
        local.setattr(owner._condition, "wait", interrupt)
        with pytest.raises(KeyboardInterrupt) as caught:
            owner.install_initial_selection("native-call", request_receipt=caller)
    assert caught.value is primary and len(waiting) == 1
    queued = waiting[0]
    assert type(queued) is host._InstallRequest
    assert queued.receipt_values == expected and queued.receipt_values is not caller
    assert queued.request_receipt_sha256 == host._RECEIPT_FROM_VALUES(expected).semantic_sha256
    assert owner._slot is queued and owner._active_nonce is queued.nonce
    assert queued.abandoned is True and queued.dispatched is False
    assert not owner._install_dispatched and not owner._stop_event.is_set()
    repeated = owner.install_initial_selection("native-call", request_receipt=_receipt())
    assert repeated.reason == "busy" and repeated.observation is None
    assert owner._slot is queued and owner._active_nonce is queued.nonce


def test_condition_cancellation_abandons_waiter_without_releasing_owned_slot(monkeypatch):
    owner = _idle_transport()
    cancel = threading.Event()
    queued = []

    def cancel_wait(timeout):
        queued.append(owner._slot)
        cancel.set()
        return False

    with monkeypatch.context() as local:
        local.setattr(owner._condition, "wait", cancel_wait)
        result = owner.install_initial_selection(
            "native-call", request_receipt=_receipt(), cancel_event=cancel
        )
    assert (result.status, result.reason, result.observation) == ("unavailable", "cancelled", None)
    assert len(queued) == 1 and queued[0].abandoned and not queued[0].dispatched
    assert owner._slot is queued[0] and owner._active_nonce is queued[0].nonce
    assert not owner._install_dispatched and not owner._stop_event.is_set()


def test_native_result_projection_detaches_original_five_values_without_live_work():
    baseline = (True, True, True, "a" * 64, "b" * 64)
    first = host._install_result("native-call", "native-incarnation", "installed", baseline)
    second = host._install_result("native-call", "native-incarnation", "installed", baseline)
    assert first == second and first is not second
    assert type(first.observation) is InitialSelectionInstallationObservation
    assert first.observation is not second.observation
    object.__setattr__(first.observation, "assignment_sha256", "0" * 64)
    object.__setattr__(first.observation, "request_receipt_sha256", "1" * 64)
    third = host._install_result("native-call", "native-incarnation", "installed", baseline)
    assert third == second and third.observation is not second.observation
    assert baseline == (True, True, True, "a" * 64, "b" * 64)


@pytest.mark.parametrize("reason", _UNAVAILABLE)
def test_pure_unavailable_projection_never_returns_retained_g_facts(reason):
    value = host._install_result("native-call", "native-incarnation", reason)
    assert (value.status, value.reason, value.observation) == ("unavailable", reason, None)
    with pytest.raises(ValueError, match=_STATE):
        host._install_result(
            "native-call",
            "native-incarnation",
            reason,
            (True, True, True, "a" * 64, "b" * 64),
        )


def test_install_requests_have_distinct_private_nonces_even_when_all_text_and_data_match():
    values = _receipt_fields(_receipt())
    digest = _receipt().semantic_sha256
    first = host._InstallRequest("same-call", "same-incarnation", _MAX_NS, None, values, digest)
    second = host._InstallRequest("same-call", "same-incarnation", _MAX_NS, None, values, digest)
    assert type(first) is type(second) is host._InstallRequest
    assert first is not second and first.nonce is not second.nonce
    assert first.call_id == second.call_id == "same-call"
    assert first.incarnation == second.incarnation == "same-incarnation"
    assert first.receipt_values == second.receipt_values == values
    assert first.request_receipt_sha256 == second.request_receipt_sha256 == digest
    assert first.result is second.result is None
    assert first.abandoned is second.abandoned is False
    assert first.dispatched is second.dispatched is False
    first.abandoned = True
    assert second.abandoned is second.dispatched is False


@pytest.mark.parametrize(
    "fault", ["nonce", "incarnation", "receipt", "call-id", "cancel-event", "deadline"]
)
def test_condition_wake_cannot_replace_original_install_request_identity(monkeypatch, fault):
    owner = _idle_transport()
    waiting = []

    def mutate(timeout):
        queued = owner._slot
        waiting.append(queued)
        if fault == "nonce":
            replacement = object()
            queued.nonce = replacement
            owner._active_nonce = replacement
        elif fault == "incarnation":
            queued.incarnation = "foreign-incarnation"
        elif fault == "call-id":
            queued.call_id = "replaced-correlation"
        elif fault == "cancel-event":
            queued.cancel_event = threading.Event()
        elif fault == "deadline":
            queued.deadline_ns += 1
        else:
            changed = (*queued.receipt_values[:1], "0" * 64, *queued.receipt_values[2:])
            queued.receipt_values = changed
            queued.request_receipt_sha256 = host._RECEIPT_FROM_VALUES(changed).semantic_sha256
        return False

    with monkeypatch.context() as local:
        local.setattr(owner._condition, "wait", mutate)
        with pytest.raises(ValueError, match=_STATE):
            owner.install_initial_selection("same-call", request_receipt=_receipt())
    assert len(waiting) == 1 and waiting[0].abandoned
    assert waiting[0].dispatched is False and owner._install_dispatched is False


def test_condition_deadline_abandons_install_without_setting_worker_stop(monkeypatch):
    owner = _idle_transport()
    clock = [100]
    waiting = []

    def advance(timeout):
        waiting.append(owner._slot)
        clock[0] = owner._slot.deadline_ns
        return False

    with monkeypatch.context() as local:
        local.setattr(host.time, "monotonic_ns", lambda: clock[0])
        local.setattr(owner._condition, "wait", advance)
        result = owner.install_initial_selection("native-call", request_receipt=_receipt())
    assert (result.status, result.reason, result.observation) == ("unavailable", "deadline", None)
    assert len(waiting) == 1 and waiting[0].abandoned and not waiting[0].dispatched
    assert owner._slot is waiting[0] and not owner._install_dispatched
    assert not owner._stop_event.is_set() and not owner._stop_latched


def _install_request(owner):
    receipt = _receipt()
    return host._InstallRequest(
        "native-call",
        owner._incarnation,
        _MAX_NS,
        None,
        _receipt_fields(receipt),
        receipt.semantic_sha256,
    )


def _complete_transport(owner, queued):
    """A caller-tail carrier, not evidence of original financial work or cleanup."""
    ended = threading.Thread(target=lambda: None, name="native-install-ack-carrier")
    try:
        ended.start()
        ended.join(2)
        assert not ended.is_alive()
    finally:
        if ended.ident is not None:
            ended.join(2)
    values = (True, True, True, queued.request_receipt_sha256, "b" * 64)
    queued._worker_thread = ended
    queued.dispatched = True
    queued.result = ("installed", values)
    owner._thread = ended
    owner._install_dispatched = owner._install_succeeded = True
    owner._install_observation = values
    owner._terminal_install = queued
    owner._slot = owner._active_nonce = None
    owner._busy = False
    owner._finalized = owner._cleanup_ok = True
    owner._phase = "stopping"
    return values


def test_terminal_ack_accepts_only_native_completion_with_an_actually_ended_thread():
    owner = _idle_transport()
    queued = _install_request(owner)
    values = _complete_transport(owner, queued)
    with owner._condition:
        assert host._install_ack(owner, queued) is None
    assert not owner._thread.is_alive() and owner._thread.ident is not None
    assert queued.result == ("installed", values)
    assert owner._stop_event.is_set() is False and owner._stop_latched is False
    assert owner._install_return_admitted is False


@pytest.mark.parametrize(
    "fault",
    [
        "request-undispatched",
        "dispatch-unlatched",
        "preparation-unadmitted",
        "different-terminal",
        "occupied-slot",
        "active-nonce",
        "busy",
        "unfinalized",
        "cleanup-incomplete",
        "cleanup-failure",
        "thread-missing",
        "failed-install",
        "abandoned",
    ],
)
def test_terminal_ack_rejects_missing_completion_facts_before_projection(fault):
    owner = _idle_transport()
    queued = _install_request(owner)
    _complete_transport(owner, queued)
    if fault == "request-undispatched":
        queued.dispatched = False
    elif fault == "dispatch-unlatched":
        owner._install_dispatched = False
    elif fault == "preparation-unadmitted":
        owner._preparation_return_admitted = False
    elif fault == "different-terminal":
        owner._terminal_install = _install_request(owner)
    elif fault == "occupied-slot":
        owner._slot, owner._active_nonce = queued, queued.nonce
    elif fault == "active-nonce":
        owner._active_nonce = object()
    elif fault == "busy":
        owner._busy = True
    elif fault == "unfinalized":
        owner._finalized = False
    elif fault == "cleanup-incomplete":
        owner._cleanup_ok = False
    elif fault == "cleanup-failure":
        owner._cleanup_failure = "cleanup_failed"
    elif fault == "thread-missing":
        owner._thread = None
    elif fault == "failed-install":
        owner._install_succeeded = False
    else:
        queued.abandoned = True
    with owner._condition, pytest.raises(ValueError, match=_STATE):
        host._install_ack(owner, queued)
    assert owner._install_return_admitted is False


def test_terminal_finally_flag_cannot_acknowledge_a_still_running_native_thread():
    owner = _idle_transport()
    queued = _install_request(owner)
    _complete_transport(owner, queued)
    release = threading.Event()
    worker = threading.Thread(target=lambda: release.wait(2), name="native-live-ack-carrier")
    try:
        worker.start()
        owner._thread = queued._worker_thread = worker
        assert owner._thread is queued._worker_thread
        assert worker.is_alive() and owner._finalized and owner._cleanup_ok
        with owner._condition, pytest.raises(ValueError, match=_STATE):
            host._install_ack(owner, queued)
        assert owner._install_return_admitted is False
    finally:
        release.set()
        if worker.ident is not None:
            worker.join(2)
        assert not worker.is_alive()


@pytest.mark.parametrize("field", ["request", "proposal"])
def test_terminal_observation_cannot_substitute_an_unrelated_request_or_proposal(field):
    owner = _idle_transport()
    queued = _install_request(owner)
    values = _complete_transport(owner, queued)
    changed = list(values)
    changed[3 if field == "request" else 4] = "0" * 64
    owner._install_observation = tuple(changed)
    queued.result = ("installed", tuple(changed))
    with owner._condition, pytest.raises(ValueError, match=_STATE):
        host._install_ack(owner, queued)
    assert owner._install_return_admitted is False


def _terminal_delivery(monkeypatch, owner):
    """Model only the caller's Condition wake and detached native completion."""
    held = []

    def acknowledge(timeout):
        queued = owner._slot
        held.append(queued)
        _complete_transport(owner, queued)
        return False

    monkeypatch.setattr(owner._condition, "wait", acknowledge)
    return held


def test_native_terminal_delivery_does_not_treat_its_matching_completion_as_a_new_stopped_call(
    monkeypatch,
):
    owner = _idle_transport()
    held = _terminal_delivery(monkeypatch, owner)
    result = owner.install_initial_selection("native-call", request_receipt=_receipt())
    assert result.status == result.reason == "installed"
    assert result.call_id == "native-call" and result.incarnation == owner._incarnation
    assert result.observation.request_receipt_sha256 == _receipt().semantic_sha256
    assert result.observation.assignment_sha256 == "b" * 64
    assert len(held) == 1 and held[0].dispatched and not held[0].abandoned
    assert owner._terminal_install is held[0] and owner._install_return_admitted is True
    assert owner._stop_event.is_set() is False and owner._stop_latched is False
    assert owner.status().phase == "stopped" and owner._thread.ident is not None
    repeated = owner.install_initial_selection("native-call", request_receipt=_receipt())
    assert (repeated.status, repeated.reason, repeated.observation) == (
        "unavailable",
        "stopped",
        None,
    )


@pytest.mark.parametrize("fault", ["clock", "cancel", "deadline", "event"])
def test_rejection_after_terminal_projection_abandons_delivery_without_erasing_native_facts(
    monkeypatch, fault
):
    owner = _idle_transport()
    held = _terminal_delivery(monkeypatch, owner)
    clock = [100]
    cancel = threading.Event()
    monkeypatch.setattr(host.time, "monotonic_ns", lambda: clock[0])
    previous = sys.getprofile()
    result_code = host._install_result.__code__
    projections = []

    def profile(frame, event, argument):
        if (
            event != "return"
            or frame.f_code is not result_code
            or type(argument) is not host.InitialSelectionInstallationResult
            or argument.status != "installed"
        ):
            return
        projections.append(fault)
        if fault == "clock":
            clock[0] = None
        elif fault == "cancel":
            cancel.set()
        elif fault == "deadline":
            clock[0] = held[0].deadline_ns
        else:
            owner._stop_event.set()

    try:
        sys.setprofile(profile)
        result = owner.install_initial_selection(
            "native-call", request_receipt=_receipt(), cancel_event=cancel
        )
    finally:
        sys.setprofile(previous)
    assert sys.getprofile() is previous and projections == [fault]
    expected = {
        "clock": "clock_invalid",
        "cancel": "cancelled",
        "deadline": "deadline",
        "event": "stopping",
    }[fault]
    assert (result.status, result.reason, result.observation) == ("unavailable", expected, None)
    assert len(held) == 1 and held[0].abandoned
    assert owner._install_return_admitted is False
    assert owner._install_observation == (True, True, True, _receipt().semantic_sha256, "b" * 64)


def test_explicit_stop_after_cleanup_denies_a_pending_install_ack_before_stopped_fast_return():
    owner = _idle_transport()
    queued = _install_request(owner)
    _complete_transport(owner, queued)
    assert owner.status().phase == "stopped" and owner._install_return_admitted is False
    assert owner._stop_event.is_set() is False
    first, second = owner.stop(), owner.stop()
    assert first.phase == second.phase == "stopped"
    assert first.cleanup_complete is second.cleanup_complete is True
    assert owner._stop_event.is_set() is True and owner._stop_latched is True
    assert owner._install_return_admitted is False
    assert owner._terminal_install is queued


def test_pending_install_stop_retains_the_first_cutoff_and_never_claims_unknown_launch_cleanup(
    monkeypatch,
):
    owner = _idle_transport()
    queued = _install_request(owner)
    owner._slot, owner._active_nonce = queued, queued.nonce
    owner._busy, owner._phase = True, "busy"
    owner._thread = threading.Thread(target=lambda: None)
    owner._shutdown_deadline = 1
    waits = []

    def forbidden(timeout):
        waits.append(timeout)
        raise AssertionError("repeated stop extended its first elapsed cutoff")

    with monkeypatch.context() as local:
        local.setattr(owner._condition, "wait", forbidden)
        first, second = owner.stop(), owner.stop()
    assert waits == [] and owner._shutdown_deadline == 1
    assert first.phase == second.phase == "stopping"
    assert first.cleanup_complete is second.cleanup_complete is False
    assert owner._thread.ident is None and owner._finalized is False
    assert owner._slot is queued and owner._active_nonce is queued.nonce
    assert owner._install_dispatched is False


@pytest.mark.parametrize(
    "kind",
    ["foreign", "head", "bool-counter", "late-hash", "two-records", "wrong-id", "list-hashes"],
)
def test_invalid_receipt_is_a_host_argument_denial_before_queue_or_clock(monkeypatch, kind):
    owner = _idle_transport()
    receipt = _receipt()
    if kind == "foreign":
        receipt = object()
    elif kind == "head":
        object.__setattr__(receipt, "previous_head", object())
    elif kind == "bool-counter":
        object.__setattr__(receipt.previous_head, "sequence", True)
    elif kind == "late-hash":
        object.__setattr__(receipt, "record_hashes", ("invalid",))
    elif kind == "two-records":
        object.__setattr__(receipt, "record_ids", (receipt.command_id, "second-record"))
        object.__setattr__(receipt, "record_hashes", ("6" * 64, "7" * 64))
        object.__setattr__(receipt.committed_head, "sequence", 9)
    elif kind == "wrong-id":
        object.__setattr__(receipt, "record_ids", ("another-request",))
    else:
        object.__setattr__(receipt, "record_hashes", ["6" * 64])
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("invalid receipt reached queued/live work")

    with monkeypatch.context() as local:
        local.setattr(host.time, "monotonic_ns", forbidden)
        local.setattr(Engine, "connect", forbidden)
        with pytest.raises(ValueError, match=_ARGUMENT):
            owner.install_initial_selection("native-call", request_receipt=receipt)
    assert effects == [] and owner._slot is owner._active_nonce is None
    assert owner._install_dispatched is False and owner._preparation_return_admitted is True


def test_host_hash_and_queue_use_snapshot_when_caller_changes_during_original_validation(
    monkeypatch,
):
    owner = _idle_transport()
    receipt = _receipt()
    expected = _receipt_fields(receipt)
    expected_digest = receipt.semantic_sha256
    previous = sys.getprofile()
    validation_code = JournalHead.__post_init__.__code__
    validations, queued = [], []
    primary = KeyboardInterrupt("native receipt snapshot observed")

    def profile(frame, event, argument):
        if event != "call" or frame.f_code is not validation_code or validations:
            return
        validations.append(frame.f_locals["self"])
        object.__setattr__(receipt, "command_id", "mutated-during-native-validation")
        object.__setattr__(receipt, "command_sha256", "0" * 64)
        object.__setattr__(receipt, "record_ids", ("mutated-during-native-validation",))
        object.__setattr__(receipt.previous_head, "sequence", 70)
        object.__setattr__(receipt.committed_head, "sequence", 71)

    def interrupt(timeout):
        queued.append(owner._slot)
        raise primary

    try:
        with monkeypatch.context() as local:
            local.setattr(owner._condition, "wait", interrupt)
            sys.setprofile(profile)
            with pytest.raises(KeyboardInterrupt) as caught:
                owner.install_initial_selection("native-call", request_receipt=receipt)
    finally:
        sys.setprofile(previous)
    assert sys.getprofile() is previous and caught.value is primary
    assert len(validations) == len(queued) == 1
    assert validations[0] is not receipt.previous_head
    assert queued[0].receipt_values == expected
    assert queued[0].request_receipt_sha256 == expected_digest
    assert queued[0].abandoned and not queued[0].dispatched


@pytest.mark.parametrize(
    "binding",
    [
        "class",
        "init",
        "install",
        "observe",
        "receipt-values",
        "receipt-copy",
        "native-receipt",
        "observation-values",
        "observation-copy",
        "observation-class",
        "observation-init",
        "observation-validate",
    ],
)
def test_host_denies_changed_direct_g_ports_before_any_substituted_callback(monkeypatch, binding):
    owner = _idle_transport()
    receipt = _receipt()
    original_class = installation._InitialSelectionInstallation
    observations = []

    def replacement(*args, **kwargs):
        observations.append("substitute")
        raise AssertionError("changed G installation/data port was invoked")

    targets = {
        "class": (installation, "_InitialSelectionInstallation"),
        "init": (original_class, "__init__"),
        "install": (original_class, "install"),
        "observe": (original_class, "observation"),
        "receipt-values": (installation, "_receipt_values"),
        "receipt-copy": (installation, "_receipt_from_values"),
        "native-receipt": (installation, "_native_receipt_values"),
        "observation-values": (installation, "_observation_values"),
        "observation-copy": (installation, "_observation_from_values"),
        "observation-class": (installation, "InitialSelectionInstallationObservation"),
        "observation-init": (InitialSelectionInstallationObservation, "__init__"),
        "observation-validate": (InitialSelectionInstallationObservation, "__post_init__"),
    }
    with monkeypatch.context() as local:
        target, name = targets[binding]
        local.setattr(target, name, replacement)
        with pytest.raises(RuntimeError, match=_BINDING):
            owner.install_initial_selection("native-call", request_receipt=receipt)
    assert observations == [] and owner._slot is owner._active_nonce is None
    assert owner._install_dispatched is False


@pytest.mark.parametrize("placement", ["class", "instance"])
def test_saved_install_entry_denies_its_own_binding_shadow_before_queue(monkeypatch, placement):
    owner = _idle_transport()
    entry = host.InitialSelectionPreparationOwner.install_initial_selection
    calls = []

    def replacement(*args, **kwargs):
        calls.append("substitute")
        raise AssertionError("changed installation host entry ran")

    with monkeypatch.context() as local:
        if placement == "class":
            local.setattr(type(owner), "install_initial_selection", replacement)
        else:
            local.setitem(vars(owner), "install_initial_selection", replacement)
        with pytest.raises(RuntimeError, match=_BINDING):
            entry(owner, "native-call", request_receipt=_receipt())
    assert calls == [] and owner._slot is None and owner._install_dispatched is False


def test_install_finalization_rejects_foreign_condition_before_entering_it():
    # Native state admission only; no Runtime, Thread or successful cleanup.
    owner = _idle_transport()
    queued = _install_request(owner)
    queued.dispatched = True
    owner._slot, owner._active_nonce = queued, queued.nonce
    owner._terminal_install, owner._install_dispatched = queued, True
    owner._busy, owner._phase = True, "stopping"
    owner._finalized, owner._cleanup_ok = False, False
    original = owner._condition
    calls = []

    class ForeignCondition:
        def __enter__(self):
            calls.append("enter")
            raise AssertionError("foreign condition callback")

        def __exit__(self, *args):
            calls.append("exit")
            raise AssertionError("foreign condition callback")

    owner._condition = ForeignCondition()
    try:
        with pytest.raises(ValueError, match=_STATE):
            host._FINALIZE_INSTALL(owner, False)
    finally:
        owner._condition = original
    assert calls == []
    assert owner._slot is queued and owner._active_nonce is queued.nonce
    assert owner._busy is True and owner._finalized is False
    assert owner._cleanup_ok is False and owner._install_return_admitted is False
    assert original.acquire(blocking=False)
    original.release()


def test_install_request_postinit_binding_is_checked_before_any_substitute_runs(monkeypatch):
    owner = _idle_transport()
    calls = []

    def replacement(*args, **kwargs):
        calls.append("postinit")
        raise AssertionError("replaced queued-request admission")

    monkeypatch.setattr(host._InstallRequest, "__post_init__", replacement)
    with pytest.raises(RuntimeError, match=_BINDING):
        owner.install_initial_selection("native-call", request_receipt=_receipt())
    assert calls == []
    assert owner._slot is owner._active_nonce is None
    assert owner._install_dispatched is False


def test_a_foreign_dead_thread_cannot_replace_the_original_dispatched_thread():
    # Two actual ended native Threads distinguish identity from liveness only.
    owner = _idle_transport()
    queued = _install_request(owner)
    _complete_transport(owner, queued)
    original = owner._thread
    foreign = threading.Thread(target=lambda: None, name="native-foreign-dead-carrier")
    try:
        foreign.start()
        foreign.join(2)
        assert not original.is_alive() and not foreign.is_alive()
        assert foreign is not original and queued._worker_thread is original
        owner._thread = foreign
        with owner._condition, pytest.raises(ValueError, match=_STATE):
            host._install_ack(owner, queued)
        assert owner._install_return_admitted is False
        assert queued._worker_thread is original
    finally:
        owner._thread = original
        if foreign.ident is not None:
            foreign.join(2)
        assert not foreign.is_alive()


@pytest.mark.parametrize("stage", ("validation", "wait"))
def test_install_uses_only_its_admitted_condition_when_callback_changes_alias(monkeypatch, stage):
    # Argument/wait admission only: no original E/G or financial work runs.
    owner = _idle_transport()
    receipt = _receipt()
    original = owner._condition
    previous = sys.getprofile()
    validation_code = JournalHead.__post_init__.__code__
    foreign_calls, changed, queued = [], [], []

    class ForeignCondition:
        def __enter__(self):
            foreign_calls.append("enter")
            raise AssertionError("foreign condition callback")

        def __exit__(self, *args):
            foreign_calls.append("exit")
            raise AssertionError("foreign condition callback")

        def notify_all(self):
            foreign_calls.append("notify")
            raise AssertionError("foreign condition callback")

    def change_alias():
        changed.append(stage)
        owner._condition = ForeignCondition()

    def profile(frame, event, argument):
        if (
            stage == "validation"
            and not changed
            and event == "call"
            and frame.f_code is validation_code
        ):
            change_alias()

    def wait(timeout):
        queued.append(owner._slot)
        change_alias()
        return False

    try:
        with monkeypatch.context() as local:
            if stage == "wait":
                local.setattr(original, "wait", wait)
            sys.setprofile(profile)
            with pytest.raises(ValueError, match=_STATE):
                owner.install_initial_selection("native-call", request_receipt=receipt)
    finally:
        sys.setprofile(previous)
        owner._condition = original
    assert sys.getprofile() is previous and changed == [stage]
    assert foreign_calls == [] and owner._install_dispatched is False
    if stage == "validation":
        assert owner._slot is None and queued == []
    else:
        assert len(queued) == 1 and queued[0] is owner._slot
        assert queued[0].abandoned and not queued[0].dispatched
        assert owner._active_nonce is queued[0].nonce
    assert original.acquire(blocking=False)
    original.release()
