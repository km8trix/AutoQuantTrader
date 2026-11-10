"""Native proof transport only; no financial verification is modeled here.

Literal result/request records and staged Condition state qualify admission,
reservation and delivery boundaries. No Runtime.verify, G/E work, original lease
or successful financial cleanup is invented. Genuine integrations own those claims.
"""

import builtins
import copy
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest
from sqlalchemy import Engine

from apps.trader import initial_selection_preparation_owner as host
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
    "already_attempted",
    "cancelled",
    "deadline",
    "stopping",
    "stopped",
    "clock_invalid",
    "verification_failed",
)
_OLD_METHODS = (
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
        configuration_path="/private/tmp/readiness-native/configuration.json",
        account_id="native-readiness-account",
        instance_lock="/private/tmp/readiness-native/instance.lock",
    )


def _idle_transport():
    """Native admission carrier only; no configured owner was started."""
    owner = _owner()
    owner._phase, owner._busy, owner._cleanup_ok = "idle", False, False
    owner._startup_deadline = owner._lifetime_deadline = owner._work_deadline = _MAX_NS
    return owner


def _unchanged_operation_fields(owner):
    return (
        owner._attempted,
        owner._preparation_return_admitted,
        owner._prepared_proposal_sha256,
        owner._install_dispatched,
        owner._terminal_install,
        owner._install_observation,
        owner._install_succeeded,
        owner._install_return_admitted,
    )


def _queued(owner, *, cancel_event=None):
    queued = host._ProofRequest("native-proof", owner._incarnation, _MAX_NS, cancel_event)
    owner._slot, owner._active_nonce = queued, queued.nonce
    owner._busy, owner._phase = True, "busy"
    return queued


@contextmanager
def _live_transport_thread(owner):
    """A native alive identity for ack only; it runs no owner/financial code."""
    release = threading.Event()
    entered = threading.Event()

    def wait_only():
        entered.set()
        release.wait(5)

    worker = threading.Thread(target=wait_only, name="native-proof-ack-carrier")
    try:
        worker.start()
        assert entered.wait(2)
        owner._thread = worker
        yield worker
    finally:
        release.set()
        if worker.ident is not None:
            worker.join(2)
        assert not worker.is_alive()


def _completed_carrier(owner, queued, worker):
    """An explicitly staged caller ack, never proof that Runtime.verify ran."""
    queued.dispatched, queued.completed = True, True
    queued._worker_thread = worker
    queued.result = "verified"


def test_result_is_exact_four_field_detached_native_data_and_frozen():
    first = host.InitialSelectionReadinessResult("ready", "verified", "call", "incarnation")
    second = host.InitialSelectionReadinessResult("ready", "verified", "call", "incarnation")
    assert first == second and first is not second
    assert (first.status, first.reason, first.call_id, first.incarnation) == (
        "ready",
        "verified",
        "call",
        "incarnation",
    )
    assert set(first.__slots__) == {"status", "reason", "call_id", "incarnation"}
    with pytest.raises(FrozenInstanceError):
        first.reason = "cancelled"


@pytest.mark.parametrize("reason", _UNAVAILABLE)
def test_each_unavailable_reason_contains_no_authority_or_private_result(reason):
    value = host.InitialSelectionReadinessResult("unavailable", reason, "call", "incarnation")
    assert value.status == "unavailable" and value.reason == reason
    assert set(value.__slots__) == {"status", "reason", "call_id", "incarnation"}


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("status", True),
        ("status", "prepared"),
        ("status", "unavailable"),
        ("reason", True),
        ("reason", "prepared"),
        ("reason", "cancelled"),
        ("call_id", ""),
        ("call_id", "a" * 129),
        ("call_id", "a/b"),
        ("call_id", None),
        ("incarnation", ""),
        ("incarnation", "a" * 129),
        ("incarnation", "a b"),
        ("incarnation", 1),
    ],
)
def test_result_rejects_native_shape_and_protocol_combinations(field, bad):
    values = dict(status="ready", reason="verified", call_id="call", incarnation="incarnation")
    values[field] = bad
    with pytest.raises(ValueError, match=_ARGUMENT):
        host.InitialSelectionReadinessResult(**values)


def test_hostile_text_is_denied_before_any_operator_or_conversion():
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("operator")
        raise AssertionError("proof data coerced hostile text")

    class Hostile(str):
        __eq__ = forbidden
        __hash__ = forbidden
        __len__ = forbidden
        __str__ = forbidden

    for field in ("status", "reason", "call_id", "incarnation"):
        values = dict(status="ready", reason="verified", call_id="call", incarnation="incarnation")
        values[field] = Hostile(values[field])
        with pytest.raises(ValueError, match=_ARGUMENT):
            host.InitialSelectionReadinessResult(**values)
    assert calls == []


def test_request_has_exactly_four_inputs_and_per_instance_runtime_fields():
    inputs = [item.name for item in fields(host._ProofRequest) if item.init]
    runtime = [item.name for item in fields(host._ProofRequest) if not item.init]
    assert inputs == ["call_id", "incarnation", "deadline_ns", "cancel_event"]
    assert set(runtime) == {
        "nonce",
        "abandoned",
        "dispatched",
        "completed",
        "result",
        "_worker_thread",
        "_admission",
    }
    first = host._ProofRequest("call", "incarnation", _MAX_NS, None)
    second = host._ProofRequest("call", "incarnation", _MAX_NS, None)
    assert type(first.nonce) is object and first.nonce is not second.nonce
    assert not first.abandoned and not first.dispatched and not first.completed
    assert first.result is first._worker_thread is None
    assert first._admission == ("call", "incarnation", None, first.nonce, _MAX_NS)
    with pytest.raises(TypeError):
        host._ProofRequest("call", "incarnation", _MAX_NS, None, nonce=object())


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("deadline_ns", True),
        ("deadline_ns", 0),
        ("deadline_ns", -1),
        ("deadline_ns", _MAX_NS + 1),
        ("cancel_event", object()),
        ("nonce", None),
        ("abandoned", 1),
        ("dispatched", 1),
        ("completed", 1),
        ("result", "verified"),
        ("_worker_thread", object()),
    ],
)
def test_request_full_native_admission_rejects_corruption(field, bad):
    queued = host._ProofRequest("call", "incarnation", _MAX_NS, None)
    setattr(queued, field, bad)
    with pytest.raises(ValueError, match=_STATE):
        host._proof_request(queued)


@pytest.mark.parametrize("field", ["call_id", "incarnation", "cancel_event", "nonce", "_admission"])
def test_private_request_admission_remains_bound_to_original_inputs(field):
    cancelled = threading.Event()
    queued = host._ProofRequest("call", "incarnation", 1000, cancelled)
    if field == "_admission":
        queued._admission = ("call", "incarnation", cancelled, queued.nonce, True)
    elif field == "cancel_event":
        queued.cancel_event = threading.Event()
    elif field == "nonce":
        queued.nonce = object()
    else:
        setattr(queued, field, "different")
    with pytest.raises(ValueError, match=_STATE):
        host._proof_request(queued)


def test_request_deadline_shortens_but_cannot_grow_above_original_admission():
    queued = host._ProofRequest("call", "incarnation", 1000, None)
    queued.deadline_ns = 999
    assert host._proof_request(queued) is queued
    queued.deadline_ns = 1001
    with pytest.raises(ValueError, match=_STATE):
        host._proof_request(queued)


@pytest.mark.parametrize("reason", ["cancelled", "deadline", "stopping", "clock_invalid"])
def test_only_admitted_quiescent_reasons_can_complete_before_dispatch(reason):
    queued = host._ProofRequest("call", "incarnation", _MAX_NS, None)
    queued.completed, queued.result = True, reason
    assert host._proof_request(queued) is queued
    assert not queued.dispatched and queued._worker_thread is None


@pytest.mark.parametrize("reason", ["verified", "verification_failed", "stopped", "prepared"])
def test_non_dispatched_completion_cannot_claim_proof_or_terminal_work(reason):
    queued = host._ProofRequest("call", "incarnation", _MAX_NS, None)
    queued.completed, queued.result = True, reason
    with pytest.raises(ValueError, match=_STATE):
        host._proof_request(queued)


def test_new_operation_keeps_original_ten_methods_and_old_result_protocols():
    assert tuple(name for name, _ in host._OWN_METHODS) == _OLD_METHODS
    assert tuple(name for name, _ in host._PROOF_METHODS) == ("check_initial_selection_readiness",)
    assert tuple(name for name, _ in host._INSTALL_METHODS) == ("install_initial_selection",)
    owner = _owner()
    assert _unchanged_operation_fields(owner) == (
        False,
        False,
        None,
        False,
        None,
        None,
        False,
        False,
    )


def test_constructor_and_native_result_have_no_io_clock_or_worker_effects(monkeypatch):
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("native proof construction reached an effect")

    with monkeypatch.context() as patch:
        for target, name in (
            (builtins, "open"),
            (Path, "open"),
            (Path, "resolve"),
            (Path, "stat"),
            (sqlite3, "connect"),
            (Engine, "connect"),
            (socket, "socket"),
            (subprocess, "Popen"),
            (threading.Thread, "start"),
            (time, "monotonic_ns"),
        ):
            patch.setattr(target, name, forbidden)
        owner = _owner()
        status = owner.status()
        value = host.InitialSelectionReadinessResult("ready", "verified", "call", "incarnation")
    assert effects == [] and owner._thread is owner._slot is None
    assert status.phase == "new" and not status.attempted
    assert value.status == "ready"


def test_foreign_receiver_never_lends_attributes_to_saved_public_entry():
    calls = []

    class Foreign:
        def __getattribute__(self, name):
            calls.append(name)
            raise AssertionError("foreign proof receiver was read")

    with pytest.raises(ValueError, match=_ARGUMENT):
        host.InitialSelectionPreparationOwner.check_initial_selection_readiness(Foreign(), "call")
    assert calls == []


def test_copied_receiver_cannot_borrow_original_condition_or_incarnation():
    owner = _owner()
    copied = copy.copy(owner)
    with pytest.raises(ValueError, match=_STATE):
        copied.check_initial_selection_readiness("call")
    assert owner._slot is owner._thread is None and owner.status().phase == "new"


@pytest.mark.parametrize("bad_id", [None, True, "", "a" * 129, "call/foreign"])
def test_bad_public_identifier_never_samples_clock_or_claims_slot(monkeypatch, bad_id):
    owner = _owner()
    calls = []

    def forbidden():
        calls.append("clock")
        raise AssertionError("bad proof identifier sampled clock")

    monkeypatch.setattr(host.time, "monotonic_ns", forbidden)
    with pytest.raises(ValueError, match=_ARGUMENT):
        owner.check_initial_selection_readiness(bad_id)
    assert calls == [] and owner._slot is None and not owner._attempted


@pytest.mark.parametrize("kind", ["object", "subclass"])
def test_non_native_event_is_rejected_before_calling_or_sampling_it(monkeypatch, kind):
    owner = _owner()
    calls = []

    class ForeignEvent(threading.Event):
        def is_set(self):
            calls.append("is_set")
            raise AssertionError("foreign cancel Event was invoked")

    cancel = object() if kind == "object" else ForeignEvent()

    def forbidden():
        calls.append("clock")
        raise AssertionError("bad proof Event sampled clock")

    monkeypatch.setattr(host.time, "monotonic_ns", forbidden)
    with pytest.raises(ValueError, match=_ARGUMENT):
        owner.check_initial_selection_readiness("call", cancel_event=cancel)
    assert calls == [] and owner._slot is None


@pytest.mark.parametrize(
    ("phase", "busy", "reason"),
    [("new", False, "not_started"), ("starting", True, "starting"), ("stopping", True, "stopping")],
)
def test_original_phase_order_precedes_attempt_and_precancel(phase, busy, reason):
    owner = _owner()
    owner._phase, owner._busy, owner._attempted = phase, busy, True
    cancel = threading.Event()
    cancel.set()
    value = owner.check_initial_selection_readiness("call", cancel_event=cancel)
    assert (value.status, value.reason) == ("unavailable", reason)
    assert owner._slot is None and owner._attempted


def test_stop_before_start_remains_terminal_and_clock_free(monkeypatch):
    owner = _owner()
    stopped = owner.stop()
    calls = []

    def forbidden():
        calls.append("clock")
        raise AssertionError("stopped proof call read a clock")

    monkeypatch.setattr(host.time, "monotonic_ns", forbidden)
    value = owner.check_initial_selection_readiness("call")
    assert stopped.phase == "stopped" and stopped.cleanup_complete
    assert (value.status, value.reason) == ("unavailable", "stopped")
    assert calls == [] and owner._thread is owner._slot is None


def test_attempted_preparation_precedes_precancel_and_cannot_be_reset_for_proof():
    owner = _idle_transport()
    owner._attempted = True
    cancel = threading.Event()
    cancel.set()
    before = _unchanged_operation_fields(owner)
    value = owner.check_initial_selection_readiness("call", cancel_event=cancel)
    assert (value.status, value.reason) == ("unavailable", "already_attempted")
    assert _unchanged_operation_fields(owner) == before and owner._slot is None


def test_precancelled_call_keeps_preparation_and_terminal_eligibility_unchanged():
    owner = _idle_transport()
    cancel = threading.Event()
    cancel.set()
    before = _unchanged_operation_fields(owner)
    value = owner.check_initial_selection_readiness("call", cancel_event=cancel)
    assert (value.status, value.reason) == ("unavailable", "cancelled")
    assert _unchanged_operation_fields(owner) == before
    assert owner._slot is owner._active_nonce is None and not owner._stop_event.is_set()


def test_reentry_precedes_clock_and_never_claims_a_proof_slot(monkeypatch):
    """A real native Thread performs only public transport reentry, no G work."""
    owner = _idle_transport()
    calls, results, errors = [], [], []

    def forbidden():
        calls.append("clock")
        raise AssertionError("owner-thread proof reentry read a clock")

    def reenter():
        try:
            results.append(owner.check_initial_selection_readiness("call"))
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(host.time, "monotonic_ns", forbidden)
    worker = threading.Thread(target=reenter, name="native-proof-reentry-carrier")
    owner._thread = worker
    try:
        worker.start()
    finally:
        if worker.ident is not None:
            worker.join(2)
    assert not worker.is_alive() and type(worker) is threading.Thread
    assert errors == [] and len(results) == 1
    value = results[0]
    assert (value.status, value.reason) == ("unavailable", "reentrant")
    assert calls == [] and owner._slot is None and not owner._attempted


def test_native_cancel_event_ignores_instance_override_without_consuming_attempt():
    owner = _idle_transport()
    cancel = threading.Event()
    cancel.set()
    calls = []

    def forbidden():
        calls.append("is_set")
        raise AssertionError("cancel Event instance callback ran")

    cancel.is_set = forbidden
    value = owner.check_initial_selection_readiness("call", cancel_event=cancel)
    assert value.reason == "cancelled" and calls == []
    assert owner._slot is None and not owner._attempted


@pytest.mark.parametrize("bad", [1, object()])
def test_non_boolean_native_event_state_cannot_enter_truthiness(bad):
    owner = _idle_transport()
    cancel = threading.Event()
    cancel._flag = bad
    with pytest.raises(ValueError, match=_STATE):
        owner.check_initial_selection_readiness("call", cancel_event=cancel)
    assert owner._slot is None and not owner._attempted


@pytest.mark.parametrize("placement", ["class", "instance"])
def test_saved_public_entry_rejects_its_method_shadow_before_callback(monkeypatch, placement):
    owner = _owner()
    method = host.InitialSelectionPreparationOwner.check_initial_selection_readiness
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("substitute")
        raise AssertionError("substituted readiness method ran")

    with monkeypatch.context() as patch:
        if placement == "class":
            patch.setattr(host.InitialSelectionPreparationOwner, method.__name__, forbidden)
        else:
            patch.setitem(vars(owner), method.__name__, forbidden)
        with pytest.raises(RuntimeError, match=_BINDING):
            method(owner, "call")
    assert calls == [] and owner._slot is owner._thread is None


@pytest.mark.parametrize(
    "name",
    [
        "_proof_bindings",
        "_PROOF_BINDINGS",
        "_proof_reason",
        "_PROOF_REASON",
        "_proof_request",
        "_PROOF_REQUEST",
        "_proof_ack",
        "_PROOF_ACK",
        "_PROOF_RESULT",
        "_VERIFY",
    ],
)
def test_finite_actual_proof_dispatch_aliases_are_checked_before_effects(monkeypatch, name):
    owner = _owner()
    method = host.InitialSelectionPreparationOwner.check_initial_selection_readiness
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(name)
        raise AssertionError("changed direct proof dispatch was invoked")

    with monkeypatch.context() as patch:
        patch.setattr(host, name, forbidden)
        patch.setattr(Engine, "connect", forbidden)
        patch.setattr(host.time, "monotonic_ns", forbidden)
        with pytest.raises(RuntimeError, match=_BINDING):
            method(owner, "call")
    assert calls == [] and owner._slot is owner._thread is None


def test_completed_proof_reservation_blocks_all_three_operations_without_a_backlog():
    owner = _idle_transport()
    queued = _queued(owner)
    receipt = JournalReceipt(
        command_id="native-request",
        command_sha256="1" * 64,
        append_sha256="2" * 64,
        previous_head=JournalHead("3" * 64, 1, "4" * 64),
        committed_head=JournalHead("3" * 64, 2, "5" * 64),
        record_ids=("native-request",),
        record_hashes=("6" * 64,),
    )
    before = _unchanged_operation_fields(owner)
    with _live_transport_thread(owner) as worker:
        _completed_carrier(owner, queued, worker)
        for correlation in (queued.call_id, "different"):
            proof = owner.check_initial_selection_readiness(correlation)
            preparation = owner.prepare_initial_selection(correlation)
            installation = owner.install_initial_selection(correlation, request_receipt=receipt)
            assert (proof.reason, preparation.reason, installation.reason) == (
                "busy",
                "busy",
                "busy",
            )
        assert owner._slot is queued and owner._active_nonce is queued.nonce
        assert queued.completed and queued.dispatched and queued.result == "verified"
        assert not queued.abandoned and owner._phase == "busy" and owner._busy
    assert _unchanged_operation_fields(owner) == before


def test_native_proof_ack_requires_the_live_exact_reserved_worker_and_no_terminal_facts():
    owner = _idle_transport()
    queued = _queued(owner)
    before = _unchanged_operation_fields(owner)
    with _live_transport_thread(owner) as worker:
        _completed_carrier(owner, queued, worker)
        with owner._condition:
            assert host._proof_ack(owner, queued) is None
        assert owner._slot is queued and owner._active_nonce is queued.nonce
        assert queued._worker_thread is worker and worker.is_alive()
    assert _unchanged_operation_fields(owner) == before


@pytest.mark.parametrize(
    "fault",
    [
        "copy",
        "slot",
        "nonce",
        "abandoned",
        "incomplete",
        "undispatched",
        "worker",
        "owner-thread",
        "attempted",
        "phase",
        "busy",
        "finalized",
    ],
)
def test_native_ack_rejects_unowned_or_ineligible_completion(fault):
    owner = _idle_transport()
    queued = _queued(owner)
    with _live_transport_thread(owner) as worker:
        _completed_carrier(owner, queued, worker)
        checked = queued
        if fault == "copy":
            checked = copy.copy(queued)
        elif fault == "slot":
            owner._slot = owner._active_nonce = None
        elif fault == "nonce":
            queued.nonce = object()
        elif fault == "abandoned":
            queued.abandoned = True
        elif fault == "incomplete":
            queued.completed, queued.result = False, None
        elif fault == "undispatched":
            queued.dispatched, queued._worker_thread = False, None
        elif fault == "worker":
            queued._worker_thread = threading.Thread(target=lambda: None)
        elif fault == "owner-thread":
            owner._thread = threading.Thread(target=lambda: None)
        elif fault == "attempted":
            owner._attempted = True
        elif fault == "phase":
            owner._phase = "idle"
        elif fault == "busy":
            owner._busy = False
        else:
            owner._finalized = True
        with owner._condition, pytest.raises(ValueError, match=_STATE):
            host._proof_ack(owner, checked)


def test_an_ended_native_thread_cannot_ack_a_nonterminal_ready_observation():
    owner = _idle_transport()
    queued = _queued(owner)
    with _live_transport_thread(owner) as worker:
        _completed_carrier(owner, queued, worker)
    assert queued._worker_thread is owner._thread is worker and not worker.is_alive()
    with owner._condition, pytest.raises(ValueError, match=_STATE):
        host._proof_ack(owner, queued)


def test_active_abandonment_cannot_release_the_worker_reservation():
    owner = _idle_transport()
    queued = _queued(owner)
    queued.abandoned = True
    before = _unchanged_operation_fields(owner)
    with owner._condition:
        assert host._proof_release(owner, queued, owner._condition) is False
    assert owner._slot is queued and owner._active_nonce is queued.nonce
    assert owner._busy and owner._phase == "busy" and not queued.completed
    assert _unchanged_operation_fields(owner) == before


def test_quiescent_abandonment_releases_only_its_exact_slot_without_resetting_eligibility():
    owner = _idle_transport()
    queued = _queued(owner)
    queued.abandoned, queued.completed, queued.result = True, True, "cancelled"
    before = _unchanged_operation_fields(owner)
    with owner._condition:
        assert host._proof_release(owner, queued, owner._condition) is True
        assert host._proof_release(owner, queued, owner._condition) is False
    assert owner._slot is owner._active_nonce is None
    assert owner._phase == "idle" and not owner._busy
    assert queued.abandoned and not queued.dispatched
    assert _unchanged_operation_fields(owner) == before


def test_old_abandoned_completion_cannot_clear_or_ack_a_later_fully_completed_request():
    owner = _idle_transport()
    old = _queued(owner)
    old.abandoned, old.completed, old.result = True, True, "deadline"
    with owner._condition:
        assert host._proof_release(owner, old, owner._condition) is True
    later = _queued(owner)
    assert later.call_id == old.call_id and later.nonce is not old.nonce
    with _live_transport_thread(owner) as worker:
        _completed_carrier(owner, later, worker)
        with owner._condition:
            assert host._proof_release(owner, old, owner._condition) is False
            with pytest.raises(ValueError, match=_STATE):
                host._proof_ack(owner, old)
            assert host._proof_ack(owner, later) is None
        assert owner._slot is later and owner._active_nonce is later.nonce
    assert old.abandoned and not owner._attempted


def test_reservation_release_rejects_a_foreign_native_condition():
    owner = _idle_transport()
    queued = _queued(owner)
    queued.abandoned, queued.completed, queued.result = True, True, "cancelled"
    with owner._condition, pytest.raises(ValueError, match=_STATE):
        host._proof_release(owner, queued, threading.Condition())
    assert owner._slot is queued and owner._active_nonce is queued.nonce


def _delivery_tail(monkeypatch, owner, worker):
    """Wake a native caller with literal completion, not a financial proof."""
    held = []

    def complete(timeout):
        queued = owner._slot
        held.append(queued)
        _completed_carrier(owner, queued, worker)
        return False

    monkeypatch.setattr(owner._condition, "wait", complete)
    return held


def test_caller_tail_retains_reservation_until_projection_and_allows_a_fresh_later_call(
    monkeypatch,
):
    owner = _idle_transport()
    before = _unchanged_operation_fields(owner)
    captured = []
    previous = sys.getprofile()
    code = host._proof_result.__code__

    def observe(frame, event, value):
        if (
            event == "return"
            and frame.f_code is code
            and type(value) is host.InitialSelectionReadinessResult
            and value.status == "ready"
        ):
            queued = owner._slot
            captured.append((queued, owner._busy, owner._phase, owner._active_nonce))

    with _live_transport_thread(owner) as worker:
        held = _delivery_tail(monkeypatch, owner, worker)
        try:
            sys.setprofile(observe)
            first = owner.check_initial_selection_readiness("same-call")
            second = owner.check_initial_selection_readiness("same-call")
        finally:
            sys.setprofile(previous)
        assert sys.getprofile() is previous
        assert first.status == second.status == "ready" and first is not second
        assert first.call_id == second.call_id == "same-call"
        assert first.incarnation == second.incarnation == owner._incarnation
        assert len(held) == len(captured) == 2
        assert captured == [
            (held[0], True, "busy", held[0].nonce),
            (held[1], True, "busy", held[1].nonce),
        ]
        assert all(queued.completed for queued in held)
        assert held[0] is not held[1] and held[0].nonce is not held[1].nonce
        assert owner._slot is owner._active_nonce is None
        assert owner._phase == "idle" and not owner._busy
    assert _unchanged_operation_fields(owner) == before


@pytest.mark.parametrize("mode", ["clock", "cancel", "deadline", "stop"])
def test_postprojection_rejection_abandons_only_its_quiescent_reservation(monkeypatch, mode):
    owner = _idle_transport()
    clock = [100]
    cancel = threading.Event()
    before = _unchanged_operation_fields(owner)
    monkeypatch.setattr(host.time, "monotonic_ns", lambda: clock[0])
    code = host._proof_result.__code__
    previous = sys.getprofile()
    observed = []

    def after_projection(frame, event, value):
        if (
            event != "return"
            or frame.f_code is not code
            or type(value) is not host.InitialSelectionReadinessResult
            or value.status != "ready"
        ):
            return
        observed.append(mode)
        if mode == "clock":
            clock[0] = None
        elif mode == "cancel":
            cancel.set()
        elif mode == "deadline":
            clock[0] = owner._slot.deadline_ns
        else:
            owner._stop_event.set()

    with _live_transport_thread(owner) as worker:
        held = _delivery_tail(monkeypatch, owner, worker)
        try:
            sys.setprofile(after_projection)
            value = owner.check_initial_selection_readiness("call", cancel_event=cancel)
        finally:
            sys.setprofile(previous)
        assert sys.getprofile() is previous
        expected = {
            "clock": "clock_invalid",
            "cancel": "cancelled",
            "deadline": "deadline",
            "stop": "stopping",
        }[mode]
        assert (value.status, value.reason) == ("unavailable", expected)
        assert observed == [mode] and len(held) == 1 and held[0].abandoned
        assert owner._slot is owner._active_nonce is None
    assert _unchanged_operation_fields(owner) == before


def test_interrupted_wait_abandons_an_active_request_without_releasing_or_stopping_it(monkeypatch):
    owner = _idle_transport()
    primary = KeyboardInterrupt("native proof wait interruption")
    held = []

    def interrupted(timeout):
        held.append(owner._slot)
        raise primary

    monkeypatch.setattr(owner._condition, "wait", interrupted)
    with pytest.raises(KeyboardInterrupt) as caught:
        owner.check_initial_selection_readiness("call")
    assert caught.value is primary and len(held) == 1
    assert owner._slot is held[0] and owner._active_nonce is held[0].nonce
    assert held[0].abandoned and not held[0].completed and not held[0].dispatched
    assert owner._busy and not owner._attempted and not owner._stop_event.is_set()


@pytest.mark.parametrize("stage", ["identifier", "wait"])
def test_original_condition_is_captured_before_validation_and_wait_callbacks(monkeypatch, stage):
    owner = _idle_transport()
    original = owner._condition
    calls = []
    held = []
    observed = []

    class ForeignCondition:
        def __enter__(self):
            calls.append("enter")
            raise AssertionError("foreign proof Condition was entered")

        def __exit__(self, *args):
            calls.append("exit")
            raise AssertionError("foreign proof Condition was exited")

        def notify_all(self):
            calls.append("notify")
            raise AssertionError("foreign proof Condition was notified")

        def wait(self, *args):
            calls.append("wait")
            raise AssertionError("foreign proof Condition was waited on")

    foreign = ForeignCondition()
    previous = sys.getprofile()
    code = host._identifier.__code__

    def after_identifier(frame, event, value):
        if event == "return" and frame.f_code is code and value == "call":
            observed.append("identifier")
            owner._condition = foreign

    def after_wait(timeout):
        held.append(owner._slot)
        observed.append("wait")
        owner._condition = foreign
        return False

    try:
        if stage == "identifier":
            sys.setprofile(after_identifier)
        else:
            monkeypatch.setattr(original, "wait", after_wait)
        with pytest.raises(ValueError, match=_STATE):
            owner.check_initial_selection_readiness("call")
    finally:
        sys.setprofile(previous)
        owner._condition = original
    assert sys.getprofile() is previous and calls == [] and observed == [stage]
    assert original.acquire(blocking=False)
    original.release()
    if stage == "wait":
        assert len(held) == 1 and held[0].abandoned
        assert owner._slot is held[0] and owner._active_nonce is held[0].nonce
    else:
        assert owner._slot is None
    assert not owner._attempted and owner._thread is None


@pytest.mark.parametrize("stage", ["identifier", "request_constructor"])
def test_native_condition_and_matching_baseline_rebind_cannot_claim_a_proof_slot(stage):
    """Only native argument/request admission is exercised, without a worker."""
    owner = _idle_transport()
    original, condition = owner._original, owner._condition
    replacement = threading.Condition(threading.Lock())
    before = _unchanged_operation_fields(owner)
    observed, replacement_calls = [], []
    previous = sys.getprofile()
    identifier_code = host._identifier.__code__
    constructor_code = host._ProofRequest.__post_init__.__code__
    condition_codes = {
        threading.Condition.__enter__.__code__,
        threading.Condition.__exit__.__code__,
        threading.Condition.wait.__code__,
        threading.Condition.notify_all.__code__,
    }

    def after_admission(frame, event, returned):
        if (
            event == "call"
            and frame.f_code in condition_codes
            and frame.f_locals.get("self") is replacement
        ):
            replacement_calls.append(frame.f_code.co_name)
        if event != "return" or observed:
            return
        if stage == "identifier":
            selected = frame.f_code is identifier_code and returned == "call"
        else:
            selected = (
                frame.f_code is constructor_code
                and type(frame.f_locals.get("self")) is host._ProofRequest
            )
        if selected:
            observed.append(stage)
            owner._condition = replacement
            owner._original = (*original[:4], replacement, *original[5:])

    try:
        sys.setprofile(after_admission)
        with pytest.raises(ValueError, match=_STATE):
            owner.check_initial_selection_readiness("call")
    finally:
        sys.setprofile(previous)
        owner._condition, owner._original = condition, original
    assert sys.getprofile() is previous
    assert observed == [stage] and replacement_calls == []
    assert owner._slot is owner._active_nonce is owner._thread is None
    assert not owner._attempted and _unchanged_operation_fields(owner) == before
    assert condition.acquire(blocking=False)
    condition.release()


def test_proof_failure_retains_primary_under_captured_lock_when_condition_baseline_changed():
    """Failure bookkeeping only; no G/Runtime work or cleanup is modeled."""
    owner = _idle_transport()
    original, condition = owner._original, owner._condition
    replacement = threading.Condition(threading.Lock())
    owner._original = (*original[:4], replacement, *original[5:])
    previous = sys.getprofile()
    state_calls, notifications = [], []
    state_code, latch_code = host._state.__code__, host._LATCH.__code__
    notify_code = threading.Condition.notify_all.__code__

    def observe(frame, event, returned):
        if event == "call" and frame.f_code in (state_code, latch_code):
            state_calls.append(frame.f_code.co_name)
        if event == "call" and frame.f_code is notify_code:
            notifications.append(frame.f_locals["self"])

    try:
        raise RuntimeError("native original proof failure")
    except RuntimeError as primary:
        traceback = primary.__traceback__
        try:
            sys.setprofile(observe)
            with condition:
                returned = host._proof_failure(owner, condition, primary)
        finally:
            sys.setprofile(previous)
            owner._original = original
        assert returned is owner._primary_error is primary
        assert primary.__traceback__ is traceback
    assert sys.getprofile() is previous
    assert owner._primary_failure == "verification_failed"
    assert owner._stop_latched and owner._phase == "stopping"
    assert state_calls == [] and notifications == [condition]
    assert not owner._stop_event.is_set()
    assert owner._cleanup_error is owner._context_error is None
    assert owner._slot is owner._active_nonce is owner._thread is None


@pytest.mark.parametrize("bad", ["unknown-proof-reason", "", 1, True])
def test_completed_dispatched_transport_request_rejects_unknown_or_non_native_reason(bad):
    """Corrupted transport only; no original financial proof is claimed."""
    owner = _idle_transport()
    queued = _queued(owner)
    with _live_transport_thread(owner) as worker:
        _completed_carrier(owner, queued, worker)
        queued.result = bad
        with pytest.raises(ValueError, match=_STATE):
            host._proof_request(queued)
        assert queued.completed and queued.dispatched
        assert owner._slot is queued and owner._active_nonce is queued.nonce
    assert not owner._attempted and owner._primary_error is None


@pytest.mark.parametrize("stage", ["request_constructor", "ready_projection"])
def test_caller_retains_original_thread_identity_across_native_callback_boundaries(
    monkeypatch, stage
):
    """Thread/ack transport only; neither carrier performs Runtime/G/E work."""
    owner, other_owner = _idle_transport(), _idle_transport()
    before = _unchanged_operation_fields(owner)
    previous = sys.getprofile()
    constructor_code = host._ProofRequest.__post_init__.__code__
    projection_code = host._proof_result.__code__
    observed, created, results = [], [], []

    with _live_transport_thread(owner) as worker, _live_transport_thread(other_owner) as other:
        assert worker is not other and worker.is_alive() and other.is_alive()
        held = _delivery_tail(monkeypatch, owner, worker)

        def after_boundary(frame, event, returned):
            if event != "return" or observed:
                return
            if stage == "request_constructor":
                if frame.f_code is not constructor_code:
                    return
                queued = frame.f_locals["self"]
                assert type(queued) is host._ProofRequest
                assert not queued.dispatched and queued._worker_thread is None
                assert owner._slot is None and owner._thread is worker
            else:
                if (
                    frame.f_code is not projection_code
                    or type(returned) is not host.InitialSelectionReadinessResult
                    or returned.status != "ready"
                ):
                    return
                queued = owner._slot
                assert held == [queued] and queued.completed and queued.dispatched
                assert queued._worker_thread is owner._thread is worker
                queued._worker_thread = other
            created.append(queued)
            observed.append(stage)
            owner._thread = other

        try:
            sys.setprofile(after_boundary)
            with pytest.raises(ValueError, match=_STATE):
                results.append(owner.check_initial_selection_readiness("changed-thread"))
            assert observed == [stage] and results == []
            assert owner._thread is other
            if stage == "request_constructor":
                assert held == [] and owner._slot is owner._active_nonce is None
                assert not created[0].dispatched and created[0]._worker_thread is None
            else:
                assert len(held) == 1 and owner._slot is created[0] is held[0]
                assert held[0].abandoned and held[0].completed and held[0].dispatched
                assert held[0]._worker_thread is other
                assert owner._active_nonce is held[0].nonce
                assert owner._busy and owner._phase == "busy"
            assert _unchanged_operation_fields(owner) == before
            assert not owner._attempted and not owner._stop_event.is_set()
        finally:
            sys.setprofile(previous)
            owner._thread = worker
            if stage == "ready_projection" and created:
                created[0]._worker_thread = worker
        assert sys.getprofile() is previous
        assert owner._thread is worker
        if stage == "ready_projection":
            assert owner._slot is held[0] and held[0]._worker_thread is worker
            assert held[0].abandoned and owner._busy
    assert not worker.is_alive() and not other.is_alive()
    # These carriers execute no worker cleanup. Retaining an abandoned slot
    # here is deliberate; this test never fabricates financial quiescence.
    if stage == "ready_projection":
        assert owner._slot is held[0] and held[0].abandoned
        assert owner._active_nonce is held[0].nonce
    assert _unchanged_operation_fields(owner) == before
