"""Modeled owner transport/lifecycle tests; these mocks prove no SQL readiness."""

import json
import threading
import time
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, asdict
from types import SimpleNamespace

import pytest

from apps.trader import continuous_readiness_owner as owner_module


def _thread_call(function):
    completed = threading.Event()
    outcome = []

    def run():
        try:
            outcome.append((True, function()))
        except BaseException as error:
            outcome.append((False, error))
        finally:
            completed.set()

    thread = threading.Thread(target=run)
    thread.start()
    return SimpleNamespace(thread=thread, completed=completed, outcome=outcome)


def _result(call):
    assert call.completed.wait(2), "controlled caller did not finish"
    call.thread.join(2)
    assert not call.thread.is_alive()
    successful, result = call.outcome[0]
    if not successful:
        raise result
    return result


def _phase(owner, phase):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        current = owner.status()
        if current.phase == phase:
            return current
        threading.Event().wait(0.001)
    pytest.fail(f"controlled owner did not reach {phase}")


@pytest.fixture
def lifecycle(monkeypatch):
    model = SimpleNamespace(
        calls=[],
        entered=threading.Event(),
        allow_open=threading.Event(),
        proof_entered=threading.Event(),
        allow_proof=threading.Event(),
        proof_exited=threading.Event(),
        cleanup_entered=threading.Event(),
        allow_cleanup=threading.Event(),
        closed=threading.Event(),
        owner_thread=None,
        stop_event=None,
        proof_count=0,
        open_error=None,
        proof_error=None,
        cleanup_error=None,
        yield_foreign=False,
        proof_hook=None,
        owners=[],
        callers=[],
    )
    model.allow_open.set()
    model.allow_proof.set()
    model.allow_cleanup.set()

    class FakeRuntime:
        def __init__(self):
            self.stop_event = model.stop_event
            self.lease_deadline_ns = time.monotonic_ns() + 60_000_000_000

        def verify(self, deadline_ns):
            model.calls.append(("proof", threading.current_thread()))
            model.proof_count += 1
            model.proof_entered.set()
            try:
                assert model.allow_proof.wait(2), "controlled proof was not released"
                if model.proof_hook is not None:
                    replacement = model.proof_hook(deadline_ns)
                    if replacement is not None:
                        return replacement
                if model.proof_error is not None:
                    raise model.proof_error
                return deadline_ns
            finally:
                model.proof_exited.set()

    @contextmanager
    def open_runtime(stop_event):
        model.owner_thread = threading.current_thread()
        model.stop_event = stop_event
        model.calls.append(("open", model.owner_thread))
        model.entered.set()
        try:
            assert model.allow_open.wait(2), "controlled startup was not released"
            if model.open_error is not None:
                raise model.open_error
            yield object() if model.yield_foreign else FakeRuntime()
        finally:
            model.calls.append(("cleanup", threading.current_thread()))
            model.cleanup_entered.set()
            try:
                assert model.allow_cleanup.wait(2), "controlled cleanup was not released"
                if model.cleanup_error is not None:
                    raise model.cleanup_error
            finally:
                model.closed.set()

    monkeypatch.setattr(owner_module, "_ReadinessRuntime", FakeRuntime)

    def create(**limits):
        selected = dict(request_ns=40_000_000, shutdown_ns=40_000_000)
        selected.update(limits)
        owner = owner_module.ContinuousReadinessOwner(
            _open_runtime=open_runtime,
            limits=owner_module.ReadinessOwnerLimits(**selected),
        )
        model.owners.append(owner)
        return owner

    model.create = create
    yield model
    # A failure must never leave an intentionally blocked owner/caller behind.
    model.allow_open.set()
    model.allow_proof.set()
    model.allow_cleanup.set()
    for owner in model.owners:
        owner.stop()
    for call in model.callers:
        call.thread.join(2)
        assert not call.thread.is_alive()
    if model.owner_thread is not None:
        model.owner_thread.join(2)
        assert not model.owner_thread.is_alive()


def test_lifecycle_constructs_verifies_and_cleans_only_on_one_owner_thread(lifecycle):
    owner = lifecycle.create()
    assert owner.status().phase == "new"
    assert owner.check("before-start").reason == "not_started"
    assert not lifecycle.entered.is_set()
    started = owner.start()
    assert started.phase == "idle"
    assert not started.cleanup_complete
    assert lifecycle.owner_thread is not threading.current_thread()
    result = owner.check("first")
    assert (result.status, result.reason, result.request_id) == ("ready", "verified", "first")
    assert result.incarnation == started.incarnation
    assert owner.status().phase == "idle"
    assert not owner.status().cleanup_complete
    stopped = owner.stop()
    assert stopped.phase == "stopped" and stopped.cleanup_complete
    lifecycle.owner_thread.join(2)
    assert not lifecycle.owner_thread.is_alive()
    assert [name for name, _thread in lifecycle.calls] == ["open", "proof", "cleanup"]
    assert all(thread is lifecycle.owner_thread for _name, thread in lifecycle.calls)
    with pytest.raises(FrozenInstanceError):
        result.status = "unavailable"


def test_same_textual_id_always_performs_a_fresh_proof(lifecycle):
    owner = lifecycle.create()
    incarnation = owner.start().incarnation
    first, second = owner.check("same-id"), owner.check("same-id")
    assert first.status == second.status == "ready"
    assert first is not second
    assert first.incarnation == second.incarnation == incarnation
    assert lifecycle.proof_count == 2


def test_busy_has_no_backlog_and_abandoned_slot_stays_owned_until_work_exits(lifecycle):
    lifecycle.allow_proof.clear()
    owner = lifecycle.create()
    owner.start()
    first = _thread_call(lambda: owner.check("timed-out"))
    lifecycle.callers.append(first)
    assert lifecycle.proof_entered.wait(1)
    second = _thread_call(lambda: owner.check("never-queued"))
    lifecycle.callers.append(second)
    assert _result(second).reason == "busy"
    assert _result(first).reason == "deadline"
    assert owner.status().phase == "busy" and owner.status().busy
    assert not lifecycle.stop_event.is_set()
    assert not lifecycle.cleanup_entered.is_set()
    assert lifecycle.proof_count == 1
    lifecycle.allow_proof.set()
    _phase(owner, "idle")
    assert lifecycle.proof_count == 1  # The rejected request never executes later.
    assert owner.check("timed-out").status == "ready"
    assert lifecycle.proof_count == 2
    assert first.outcome[0][1].status == "unavailable"


def test_already_cancelled_request_never_reaches_runtime(lifecycle):
    owner = lifecycle.create()
    owner.start()
    cancelled = threading.Event()
    cancelled.set()
    result = owner.check("cancelled-before-claim", cancel_event=cancelled)
    assert result.status == "unavailable" and result.reason == "cancelled"
    assert lifecycle.proof_count == 0
    assert not lifecycle.stop_event.is_set()
    cancelled.clear()
    assert owner.check("cancelled-before-claim", cancel_event=cancelled).status == "ready"
    assert lifecycle.proof_count == 1


def test_cancellation_during_work_discards_completion_without_stopping_owner(lifecycle):
    lifecycle.allow_proof.clear()
    owner = lifecycle.create(request_ns=1_000_000_000)
    owner.start()
    cancelled = threading.Event()
    first = _thread_call(lambda: owner.check("cancelled-during", cancel_event=cancelled))
    lifecycle.callers.append(first)
    assert lifecycle.proof_entered.wait(1)
    cancelled.set()
    assert _result(first).reason == "cancelled"
    assert owner.status().busy
    assert not lifecycle.stop_event.is_set()
    lifecycle.allow_proof.set()
    _phase(owner, "idle")
    cancelled.clear()
    assert owner.check("cancelled-during", cancel_event=cancelled).status == "ready"
    assert lifecycle.proof_count == 2


def test_stop_of_stalled_work_retains_resources_until_actual_completion(lifecycle):
    lifecycle.allow_proof.clear()
    owner = lifecycle.create(request_ns=1_000_000_000)
    owner.start()
    caller = _thread_call(lambda: owner.check("blocked"))
    lifecycle.callers.append(caller)
    assert lifecycle.proof_entered.wait(1)
    stopping = owner.stop()
    assert stopping.phase == "stopping" and stopping.busy
    assert not stopping.cleanup_complete
    assert lifecycle.owner_thread.is_alive()
    assert lifecycle.stop_event.is_set()
    assert not lifecycle.cleanup_entered.is_set()
    assert owner.check("after-stop").status == "unavailable"
    lifecycle.stop_event.clear()
    assert owner.check("clear-is-not-rearm").status == "unavailable"
    lifecycle.allow_proof.set()
    assert _result(caller).status == "unavailable"
    stopped = _phase(owner, "stopped")
    assert stopped.cleanup_complete
    lifecycle.owner_thread.join(2)
    assert not lifecycle.owner_thread.is_alive()
    assert [name for name, _thread in lifecycle.calls].count("cleanup") == 1
    assert owner.start().phase == "stopped"
    assert owner.check("no-restart").status == "unavailable"


def test_shutdown_wait_expiry_during_cleanup_is_not_cleanup_complete(lifecycle):
    lifecycle.allow_cleanup.clear()
    owner = lifecycle.create()
    owner.start()
    stopping = owner.stop()
    assert lifecycle.cleanup_entered.wait(1)
    assert stopping.phase == "stopping" and not stopping.cleanup_complete
    assert lifecycle.owner_thread.is_alive()
    lifecycle.allow_cleanup.set()
    assert _phase(owner, "stopped").cleanup_complete
    lifecycle.owner_thread.join(2)
    assert not lifecycle.owner_thread.is_alive()


def test_startup_deadline_does_not_clean_resources_from_caller(lifecycle):
    lifecycle.allow_open.clear()
    owner = lifecycle.create(startup_ns=30_000_000)
    started = owner.start()
    assert lifecycle.entered.is_set()
    assert started.phase == "stopping"
    assert started.primary_failure == "startup_deadline"
    assert not started.cleanup_complete
    assert lifecycle.owner_thread.is_alive()
    assert not lifecycle.cleanup_entered.is_set()
    lifecycle.allow_open.set()
    assert _phase(owner, "stopped").cleanup_complete
    assert lifecycle.proof_count == 0


def test_stop_during_startup_never_claims_thread_completion_early(lifecycle):
    lifecycle.allow_open.clear()
    owner = lifecycle.create()
    starting = _thread_call(owner.start)
    lifecycle.callers.append(starting)
    assert lifecycle.entered.wait(1)
    stopping = owner.stop()
    assert stopping.phase == "stopping" and not stopping.cleanup_complete
    assert lifecycle.owner_thread.is_alive() and lifecycle.stop_event.is_set()
    assert not lifecycle.cleanup_entered.is_set()
    lifecycle.allow_open.set()
    _result(starting)
    assert _phase(owner, "stopped").cleanup_complete
    assert lifecycle.proof_count == 0


def test_idle_lifetime_expires_without_a_caller_and_does_not_restart(lifecycle):
    owner = lifecycle.create(lifetime_ns=180_000_000, startup_ns=100_000_000)
    assert owner.start().phase == "idle"
    assert not owner.status().cleanup_complete
    assert lifecycle.cleanup_entered.wait(2)
    result = _phase(owner, "stopped")
    assert result.primary_failure == "lifetime_expired"
    assert result.cleanup_complete
    assert lifecycle.proof_count == 0
    assert owner.start().phase == "stopped"


@pytest.mark.parametrize("location", ["startup", "runtime", "both"])
def test_primary_and_cleanup_failures_have_separate_static_codes(lifecycle, location):
    class PrivateFailure(BaseException):
        def __str__(self):
            pytest.fail("private exception must not be stringified")

        def __repr__(self):
            pytest.fail("private exception must not be represented")

    owner = lifecycle.create()
    if location == "startup":
        lifecycle.open_error = PrivateFailure()
    else:
        lifecycle.proof_error = PrivateFailure()
    if location == "both":
        lifecycle.cleanup_error = PrivateFailure()
    started = owner.start()
    if location == "startup":
        assert started.primary_failure == "startup_failed"
    else:
        result = owner.check("private-failure")
        assert result.status == "unavailable"
    stopped = _phase(owner, "stopped")
    assert stopped.primary_failure == (
        "startup_failed" if location == "startup" else "runtime_failed"
    )
    assert stopped.cleanup_failure == ("cleanup_failed" if location == "both" else None)
    assert stopped.cleanup_complete is (location != "both")
    assert set(asdict(stopped)) == {
        "phase",
        "busy",
        "cleanup_complete",
        "primary_failure",
        "cleanup_failure",
        "incarnation",
    }
    assert len(json.dumps(asdict(stopped))) < 1024
    assert lifecycle.closed.is_set()
    assert all(thread is lifecycle.owner_thread for _name, thread in lifecycle.calls)


def test_cleanup_failure_without_primary_is_not_successful_shutdown(lifecycle):
    lifecycle.cleanup_error = RuntimeError("private cleanup payload")
    owner = lifecycle.create()
    owner.start()
    assert owner.check("completed-before-cleanup-failure").status == "ready"
    owner.stop()
    stopped = _phase(owner, "stopped")
    assert stopped.primary_failure is None
    assert stopped.cleanup_failure == "cleanup_failed"
    assert not stopped.cleanup_complete


def test_failed_partial_startup_cleanup_is_not_reported_complete(lifecycle):
    lifecycle.open_error = BaseExceptionGroup(
        "private setup and cleanup", [ValueError("private setup"), ValueError("private close")]
    )
    owner = lifecycle.create()
    owner.start()
    stopped = _phase(owner, "stopped")
    assert stopped.primary_failure == "startup_failed"
    assert stopped.cleanup_failure == "cleanup_failed"
    assert not stopped.cleanup_complete and lifecycle.proof_count == 0


def test_foreign_runtime_is_rejected_without_calling_it(lifecycle):
    lifecycle.yield_foreign = True
    owner = lifecycle.create()
    started = owner.start()
    assert started.phase in ("stopping", "stopped")
    stopped = _phase(owner, "stopped")
    assert stopped.primary_failure == "startup_failed"
    assert lifecycle.proof_count == 0
    assert stopped.cleanup_complete


def test_reentrant_public_operations_never_wait_for_the_owner_itself(lifecycle):
    owner = lifecycle.create(request_ns=1_000_000_000)
    nested = []

    def reenter(_deadline):
        nested.append(owner.check("nested"))
        nested.append(owner.start())
        nested.append(owner.stop())

    lifecycle.proof_hook = reenter
    owner.start()
    result = owner.check("outer")
    assert nested[0].reason == "reentrant"
    assert nested[1].phase in ("busy", "stopping")
    assert nested[2].phase == "stopping" and not nested[2].cleanup_complete
    assert result.status == "unavailable"
    assert _phase(owner, "stopped").cleanup_complete
    assert lifecycle.proof_count == 1


def test_exact_deadline_completion_cannot_be_delivered_as_ready(lifecycle, monkeypatch):
    observed = [time.monotonic_ns()]
    monkeypatch.setattr(owner_module.time, "monotonic_ns", lambda: observed[0])
    owner = lifecycle.create()
    owner.start()

    def finish_at_deadline(deadline):
        observed[0] = deadline

    lifecycle.proof_hook = finish_at_deadline
    result = owner.check("exact-deadline")
    assert result.status == "unavailable" and result.reason == "deadline"
    assert lifecycle.proof_count == 1
    assert not lifecycle.stop_event.is_set()
    lifecycle.proof_hook = None
    assert owner.check("exact-deadline").status == "ready"
    assert lifecycle.proof_count == 2


@pytest.mark.parametrize("bad", [True, -1, 1.0, None])
def test_invalid_or_regressed_monotonic_observation_stops_incarnation(lifecycle, monkeypatch, bad):
    sampled = [time.monotonic_ns()]
    monkeypatch.setattr(owner_module.time, "monotonic_ns", lambda: sampled[0])
    owner = lifecycle.create()
    owner.start()
    sampled[0] = bad
    result = owner.check("invalid-clock")
    assert result.status == "unavailable"
    assert _phase(owner, "stopped").primary_failure == "clock_invalid"
    assert lifecycle.proof_count == 0
    assert lifecycle.stop_event.is_set()


@pytest.mark.parametrize("invalid", [True, 0, "deadline", "extension"])
def test_runtime_cannot_return_a_non_native_or_extended_deadline(lifecycle, invalid):
    owner = lifecycle.create()

    def bad_deadline(deadline):
        return deadline + 1 if invalid == "extension" else invalid

    lifecycle.proof_hook = bad_deadline
    owner.start()
    assert owner.check("invalid-runtime-deadline").status == "unavailable"
    stopped = _phase(owner, "stopped")
    assert stopped.primary_failure == "runtime_failed"
    assert lifecycle.proof_count == 1


def test_explicit_new_owner_has_new_incarnation_and_no_old_result(lifecycle):
    first = lifecycle.create()
    first.start()
    old = first.check("same-id")
    assert old.status == "ready"
    assert first.stop().cleanup_complete
    lifecycle.owner_thread.join(2)
    assert not lifecycle.owner_thread.is_alive()
    second = lifecycle.create()
    second.start()
    new = second.check("same-id")
    assert new.status == "ready" and new.incarnation != old.incarnation
    assert first.check("same-id").status == "unavailable"
    assert lifecycle.proof_count == 2


@pytest.mark.parametrize("bad", [None, True, 7, "", " padded", "bad/slash", "x" * 129])
def test_invalid_request_identifiers_have_no_runtime_effects(lifecycle, bad):
    owner = lifecycle.create()
    owner.start()
    with pytest.raises(ValueError):
        owner.check(bad)
    assert lifecycle.proof_count == 0
    assert owner.status().phase == "idle"


@pytest.mark.parametrize("bad", [object(), True, threading.Event])
def test_invalid_cancel_argument_has_no_runtime_effects(lifecycle, bad):
    owner = lifecycle.create()
    owner.start()
    with pytest.raises(ValueError):
        owner.check("invalid-event", cancel_event=bad)
    assert lifecycle.proof_count == 0
    assert owner.status().phase == "idle"


def test_exact_event_override_is_data_and_never_a_caller_callback(lifecycle):
    owner = lifecycle.create()
    owner.start()
    event = threading.Event()
    called = []

    def forbidden():
        called.append(True)
        pytest.fail("owner must use the captured native Event sampler")

    event.is_set = forbidden
    assert owner.check("native-event", cancel_event=event).status == "ready"
    assert called == [] and lifecycle.proof_count == 1


@pytest.mark.parametrize("flag", [0, 1, "trap"])
def test_corrupted_event_flag_is_rejected_without_truth_conversion(lifecycle, flag):
    calls = []

    class TruthTrap:
        def __bool__(self):
            calls.append(True)
            pytest.fail("native event state must not invoke truth conversion")

    owner = lifecycle.create()
    owner.start()
    event = threading.Event()
    event._flag = TruthTrap() if flag == "trap" else flag
    with pytest.raises(ValueError, match=r"^READINESS_EVENT_STATE_INVALID$"):
        owner.check("corrupt-native-event", cancel_event=event)
    assert calls == [] and lifecycle.proof_count == 0
    assert owner.status().phase == "idle"
    event._flag = False
    assert owner.check("corrupt-native-event", cancel_event=event).status == "ready"


def test_corrupted_private_stop_flag_stops_without_a_truth_callback(lifecycle):
    calls = []

    class TruthTrap:
        def __bool__(self):
            calls.append(True)
            pytest.fail("private stop corruption must not invoke truth conversion")

    owner = lifecycle.create()
    owner.start()
    lifecycle.stop_event._flag = TruthTrap()
    assert owner.check("corrupt-stop").status == "unavailable"
    assert _phase(owner, "stopped").primary_failure == "stop_invalid"
    assert calls == [] and lifecycle.proof_count == 0


def test_interrupted_wait_abandons_slot_without_delivering_or_stopping(lifecycle, monkeypatch):
    class Interrupted(BaseException):
        pass

    marker = Interrupted()
    lifecycle.allow_proof.clear()
    owner = lifecycle.create(request_ns=1_000_000_000)
    owner.start()
    caller = threading.current_thread()
    original_wait = owner._condition.wait
    fired = []

    def interrupted_wait(timeout=None):
        if threading.current_thread() is caller and lifecycle.proof_entered.is_set() and not fired:
            fired.append(True)
            raise marker
        return original_wait(timeout)

    monkeypatch.setattr(owner._condition, "wait", interrupted_wait)
    with pytest.raises(Interrupted) as caught:
        owner.check("interrupted")
    assert caught.value is marker
    with owner._condition:
        assert owner._slot is not None and owner._slot.abandoned
    assert owner.status().busy and not lifecycle.stop_event.is_set()
    assert owner.check("not-queued-after-interruption").reason == "busy"
    lifecycle.allow_proof.set()
    _phase(owner, "idle")
    assert owner.check("interrupted").status == "ready"
    assert lifecycle.proof_count == 2 and fired == [True]


@pytest.mark.parametrize("field", ["startup_ns", "request_ns", "shutdown_ns", "lifetime_ns"])
@pytest.mark.parametrize("bad", [0, -1, True, 1.0, float("nan"), "1000"])
def test_limits_require_positive_native_integers(field, bad):
    with pytest.raises(ValueError):
        owner_module.ReadinessOwnerLimits(**{field: bad})


@pytest.mark.parametrize(
    ("field", "maximum"),
    [
        ("startup_ns", 10_000_000_000),
        ("request_ns", 5_000_000_000),
        ("shutdown_ns", 1_000_000_000),
        ("lifetime_ns", 60_000_000_000),
    ],
)
def test_limits_cannot_enlarge_selected_component_bounds(field, maximum):
    with pytest.raises(ValueError):
        owner_module.ReadinessOwnerLimits(**{field: maximum + 1})


def test_shutdown_reserve_must_precede_the_native_lifetime_boundary():
    with pytest.raises(ValueError, match=r"^READINESS_SHUTDOWN_RESERVE_REQUIRED$"):
        owner_module.ReadinessOwnerLimits(shutdown_ns=1, lifetime_ns=1)


def test_mutated_limits_cannot_bypass_constructor_revalidation():
    limits = owner_module.ReadinessOwnerLimits()
    object.__setattr__(limits, "request_ns", 5_000_000_001)

    def forbidden(_stop):
        pytest.fail("invalid limits must not open resources")

    with pytest.raises(ValueError, match=r"^READINESS_LIMIT_INVALID$"):
        owner_module.ContinuousReadinessOwner(_open_runtime=forbidden, limits=limits)


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, RuntimeError])
def test_async_start_interruption_does_not_infer_cleanup_from_not_alive(
    lifecycle, monkeypatch, error_type
):
    # Model the unacknowledged-launch boundary: is_alive is false, but an
    # asynchronous exception supplies no evidence that native launch failed.
    # This branch launches no thread; it must remain honestly indeterminate.
    starts = []

    class UnacknowledgedThread(threading.Thread):
        def start(self):
            starts.append(self)
            raise error_type("private unacknowledged startup")

    monkeypatch.setattr(owner_module, "Thread", UnacknowledgedThread)
    owner = lifecycle.create()
    try:
        result = owner.start()
        assert len(starts) == 1 and not starts[0].is_alive()
        assert result.phase == "stopping" and result.busy
        assert result.primary_failure == "startup_failed"
        assert not result.cleanup_complete and result.cleanup_failure is None
        assert owner.check("unacknowledged-start").status == "unavailable"
        assert owner.start().phase == "stopping"
        assert len(starts) == 1
        assert lifecycle.calls == []
    finally:
        stopped = owner.stop()
        assert stopped.phase == "stopping" and not stopped.cleanup_complete
        assert all(not thread.is_alive() for thread in starts)
        # No join is valid for this deliberately never-started model Thread.


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, RuntimeError])
def test_real_started_thread_interruption_waits_for_actual_exit_before_cleanup(
    lifecycle, monkeypatch, error_type
):
    native_entered = threading.Event()
    allow_owner_entry = threading.Event()
    actual_exited = threading.Event()
    starts = []

    class InterruptedStartedThread(threading.Thread):
        def start(self):
            super().start()
            starts.append(self)
            raise error_type("private already-launched startup")

        def run(self):
            native_entered.set()
            try:
                assert allow_owner_entry.wait(2), "controlled native owner was not released"
                super().run()
            finally:
                actual_exited.set()

    monkeypatch.setattr(owner_module, "Thread", InterruptedStartedThread)
    owner = lifecycle.create()
    try:
        result = owner.start()
        assert native_entered.wait(1)
        assert len(starts) == 1 and starts[0].is_alive()
        assert result.phase == "stopping" and not result.cleanup_complete
        assert result.primary_failure == "startup_failed"
        assert owner.stop().cleanup_complete is False
        assert not actual_exited.is_set()
        assert lifecycle.calls == []
        assert owner.check("after-interrupted-launch").status == "unavailable"
        allow_owner_entry.set()
        starts[0].join(2)
        assert not starts[0].is_alive() and actual_exited.is_set()
        stopped = owner.status()
        assert stopped.phase == "stopped" and stopped.cleanup_complete
        assert stopped.primary_failure == "startup_failed" and stopped.cleanup_failure is None
        # The latched interruption is observed before opening the builder. No
        # resource acquisition/cleanup or readiness proof is invented afterward.
        assert lifecycle.calls == [] and lifecycle.proof_count == 0
        assert owner.start().phase == "stopped" and len(starts) == 1
    finally:
        allow_owner_entry.set()
        for thread in starts:
            thread.join(2)
            assert not thread.is_alive()
        owner.stop()


def test_positive_native_monotonic_regression_stops_without_a_proof(lifecycle, monkeypatch):
    sampled = [time.monotonic_ns()]
    assert type(sampled[0]) is int and sampled[0] > 1
    monkeypatch.setattr(owner_module.time, "monotonic_ns", lambda: sampled[0])
    owner = lifecycle.create()
    assert owner.start().phase == "idle"
    sampled[0] -= 1  # Still a valid positive native integer; only order is wrong.
    result = owner.check("one-nanosecond-regression")
    assert result.status == "unavailable"
    stopped = _phase(owner, "stopped")
    assert stopped.primary_failure == "clock_invalid" and stopped.cleanup_complete
    assert lifecycle.proof_count == 0 and lifecycle.stop_event.is_set()
    lifecycle.owner_thread.join(2)
    assert not lifecycle.owner_thread.is_alive()
