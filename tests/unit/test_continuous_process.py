"""Real local process boundaries using the explicit repository fixture child."""

import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from packages.application import continuous_process as process_module
from packages.application.continuous_process import (
    ContinuousProcessLimits,
    ContinuousProcessRequest,
    ContinuousProcessSupervisor,
    _encode,
)
from packages.application.personal_runtime import DuplicateRuntimeError, LocalInstanceGuard
from packages.domain.research_job_contracts import ObjectRef


@pytest.fixture
def case(tmp_path):
    tmp_path.chmod(0o700)
    config = tmp_path / "config.json"
    pid_file = tmp_path / "child.pid"
    config.write_text(json.dumps({"pid_file": str(pid_file)}))
    config.chmod(0o600)
    request = ContinuousProcessRequest(
        "fixture-account",
        "success",
        config,
        limits=ContinuousProcessLimits(wall_seconds=4, cpu_seconds=3),
    )
    return tmp_path, pid_file, request, ContinuousProcessSupervisor(artifact_directory=tmp_path)


def run(case, mode="success", *, stop=lambda: False, fence=lambda: True, limits=None):
    root, _pid, request, supervisor = case
    request = replace(request, operation_id=mode, limits=limits or request.limits)
    with LocalInstanceGuard(root / "instance.lock") as guard:
        return supervisor._run_fixture_for_test(
            request, lock_descriptor=guard.fileno(), stop_requested=stop, fence_is_current=fence
        )


def assert_reaped(pid_file):
    if pid_file.exists():
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)


def test_actual_child_receipt_is_bounded_opaque_and_environment_is_clean(case, monkeypatch):
    monkeypatch.setenv("CONTINUOUS_TEST_SECRET", "fixture-do-not-propagate")
    result = run(case, "environment")
    assert result.status == "completed" and result.reason == "completed", result
    assert result.receipt is not None
    payload = result.receipt.path.read_bytes()
    assert payload == b'{"fixture":true,"trading_authorized":false}'
    assert result.receipt.byte_count == len(payload)
    assert result.receipt.object_sha256 == sha256(payload).hexdigest()
    assert result.receipt.path.stat().st_mode & 0o777 == 0o600
    assert_reaped(case[1])
    assert not tuple(case[0].glob(".continuous-operation-*"))


@pytest.mark.parametrize("mode", ["early_eof_success", "early_eof_stall"])
def test_early_output_eof_is_not_child_exit(case, mode):
    started = time.monotonic()
    result = run(case, mode, limits=replace(case[2].limits, wall_seconds=2))
    assert time.monotonic() - started < 2.3
    assert result.reason == ("completed" if mode == "early_eof_success" else "deadline")
    assert (result.receipt is not None) == (mode == "early_eof_success")
    assert case[3]._cleanup is not None and case[3]._cleanup.complete
    assert_reaped(case[1])


@pytest.mark.parametrize("mode", ["descendant_holds_output", "descendant_closes_output"])
def test_actual_zombie_leader_with_live_descendant_requires_full_group_cleanup(
    case, monkeypatch, mode
):
    original_launch = process_module.subprocess.Popen
    original_killpg = process_module.os.killpg
    owned = []
    signals = []
    waits = []

    def launch(*args, **kwargs):
        child = original_launch(*args, **kwargs)
        if "tests.fixtures.continuous_process_child" in args[0]:
            owned.append(child)
            original_wait = child.wait

            def forbidden_poll():
                raise AssertionError("observing the actual leader must not reap it")

            def wait(*, timeout):
                waits.append((child.pid, tuple(signals)))
                return original_wait(timeout=timeout)

            monkeypatch.setattr(child, "poll", forbidden_poll)
            monkeypatch.setattr(child, "wait", wait)
        return child

    def signal_group(pid, sig):
        if owned and pid == owned[0].pid:
            if sig:
                assert not waits and owned[0].returncode is None
            signals.append(sig)
        return original_killpg(pid, sig)

    monkeypatch.setattr(process_module.subprocess, "Popen", launch)
    monkeypatch.setattr(process_module.os, "killpg", signal_group)
    result = run(case, mode)
    assert len(owned) == 1 and owned[0].returncode == 0
    assert waits == [(owned[0].pid, (signal.SIGTERM, signal.SIGKILL))]
    assert all(sig == 0 for sig in signals[2:])
    cleanup = case[3]._cleanup
    assert cleanup is not None and cleanup.reaped
    descendant = json.loads(case[1].with_suffix(".descendant.json").read_text())
    assert descendant["pgid"] == owned[0].pid and descendant["pid"] != owned[0].pid

    # This is observation only: an orphan is not our owned child and its stored
    # PID must never authorize destructive cleanup. Its own short expiry also
    # bounds a failing test. A zombie is dead but still prevents group absence.
    state = subprocess.run(
        ("/bin/ps", "-o", "state=", "-p", str(descendant["pid"])),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        timeout=0.1,
        check=False,
    )
    absent = state.returncode == 1 and not state.stdout.strip()
    dead = (
        state.returncode == 0
        and len(state.stdout) <= 32
        and len(state.stdout.split()) == 1
        and state.stdout.strip().startswith(b"Z")
        and all(value in b"+<>AELNSsVWXl" for value in state.stdout.strip()[1:])
    )
    assert absent or dead, "the actual descendant must be terminated"
    assert_reaped(case[1])
    if cleanup.complete:
        assert result.status == "completed" and result.receipt is not None
        with pytest.raises(ProcessLookupError):
            original_killpg(owned[0].pid, 0)
    else:
        # Some Linux init/subreaper configurations retain orphan zombies. This
        # is recorded incomplete cleanup, never a successful worker acceptance.
        assert result.reason == "cleanup_incomplete" and result.receipt is None
        assert not cleanup.group_absent
        assert cleanup.issues[-1] in (
            "group_still_present",
            "group_probe_denied",
            "group_probe_failed",
        )
        assert not tuple(case[0].glob("continuous-receipt-*"))


def test_unavailable_child_observation_rejects_receipt_but_still_cleans_owned_child(
    case, monkeypatch
):
    def unavailable(*_args, **_kwargs):
        raise ValueError("fixture unavailable observation")

    monkeypatch.setattr(process_module, "_observe_child", unavailable)
    result = run(case, "stall")
    assert result.reason == "child_observation_failed" and result.receipt is None
    assert case[3]._cleanup is not None and case[3]._cleanup.complete
    assert "cleanup_observation_unavailable" in case[3]._cleanup.issues
    assert_reaped(case[1])


def test_incomplete_cleanup_blocks_reuse_without_new_launch(case, monkeypatch):
    case[3]._cleanup_complete = False

    def forbidden(*_args, **_kwargs):
        raise AssertionError("uncertain cleanup must block launch")

    monkeypatch.setattr(process_module.subprocess, "Popen", forbidden)
    result = run(case)
    assert result.reason == "cleanup_incomplete" and result.receipt is None


@pytest.mark.parametrize(
    "output,exited,rss", [(b"Ss 1024\n", False, 1048576), (b"Z+ 0\n", True, 0)]
)
def test_child_observation_reads_only_state_and_rss_without_reaping(
    monkeypatch, output, exited, rss
):
    calls = []

    def ps(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=output)

    monkeypatch.setattr(process_module.subprocess, "run", ps)
    assert process_module._observe_ps_child(1234) == process_module._ChildObservation(exited, rss)
    assert calls[0][0] == ("/bin/ps", "-o", "state=,rss=", "-p", "1234")
    assert calls[0][1]["timeout"] == 0.1
    assert calls[0][1]["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


@pytest.mark.parametrize(
    "code,output",
    [
        (1, b""),
        (0, b""),
        (0, b"Z"),
        (0, b"Zombie 0"),
        (0, b"? 0"),
        (0, b"S -1"),
        (0, b"S 1\nZ 0"),
        (0, b"Z " + b"0" * 64),
    ],
)
def test_unavailable_or_unknown_child_state_is_not_exit(monkeypatch, code, output):
    monkeypatch.setattr(
        process_module.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, code, stdout=output),
    )
    with pytest.raises(ValueError, match="child observation unavailable"):
        process_module._observe_ps_child(1234)


@pytest.fixture
def cleanup_model(monkeypatch):
    calls = []
    clock = [0.0]
    monkeypatch.setattr(process_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        process_module.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay)
    )

    class OwnedChild:
        pid = 1234
        returncode = None

        def wait(self, *, timeout):
            calls.append(("wait", timeout))
            self.returncode = 0
            return 0

        def poll(self):
            raise AssertionError("poll must not reap during observation or cleanup")

        def kill(self):
            raise AssertionError("Popen.kill can reap before signalling")

    child = OwnedChild()

    def killpg(pid, sig):
        assert pid == child.pid
        calls.append(("signal", sig))
        if sig:
            assert child.returncode is None, "destructive signal after reap"
        else:
            assert child.returncode is not None
            raise ProcessLookupError

    def observe(pid, *, timeout=0.1):
        assert pid == child.pid and timeout <= 0.1
        calls.append(("observe", timeout))
        return process_module._ChildObservation(False, 1024)

    monkeypatch.setattr(process_module.os, "killpg", killpg)
    monkeypatch.setattr(process_module, "_observe_child", observe)
    return child, calls, clock


@pytest.mark.parametrize("exited", [False, True])
def test_owned_cleanup_sends_final_group_signal_before_its_only_reap(cleanup_model, exited):
    child, calls, clock = cleanup_model
    result = process_module._terminate_owned_child(child, deadline=0.75, exit_observed=exited)
    assert result.complete and result.returncode == 0 and not result.issues
    assert [item for item in calls if item[0] == "signal"] == [
        ("signal", signal.SIGTERM),
        ("signal", signal.SIGKILL),
        ("signal", 0),
    ]
    wait_positions = [i for i, item in enumerate(calls) if item[0] == "wait"]
    assert len(wait_positions) == 1
    assert calls[wait_positions[0] - 1] == ("signal", signal.SIGKILL)
    assert calls[wait_positions[0] + 1] == ("signal", 0)
    assert clock[0] <= 0.25
    assert any(item[0] == "observe" for item in calls) != exited


def test_observation_failure_during_cleanup_is_reported_and_does_not_skip_final_signal(
    cleanup_model, monkeypatch
):
    child, calls, _clock = cleanup_model

    def unavailable(*_args, **_kwargs):
        raise ValueError("unknown state")

    monkeypatch.setattr(process_module, "_observe_child", unavailable)
    result = process_module._terminate_owned_child(child, deadline=0.75, exit_observed=False)
    assert result.complete and result.issues == ("cleanup_observation_unavailable",)
    assert [call[1] for call in calls if call[0] == "signal"] == [signal.SIGTERM, signal.SIGKILL, 0]


@pytest.mark.parametrize("group_after_reap", ["absent", "present", "denied"])
def test_zombie_eperm_is_resolved_only_by_reap_and_independent_group_absence(
    cleanup_model, monkeypatch, group_after_reap
):
    child, calls, clock = cleanup_model

    def denied_group(pid, sig):
        assert pid == child.pid
        calls.append(("signal", sig))
        if sig:
            assert child.returncode is None
            raise PermissionError
        assert child.returncode == 0
        if group_after_reap == "absent":
            raise ProcessLookupError
        if group_after_reap == "denied":
            raise PermissionError

    monkeypatch.setattr(process_module.os, "killpg", denied_group)
    result = process_module._terminate_owned_child(child, deadline=0.75, exit_observed=True)
    assert result.complete == (group_after_reap == "absent")
    assert result.issues[:2] == ("term_denied", "kill_denied")
    if group_after_reap != "absent":
        assert result.issues[-1] == (
            "group_still_present" if group_after_reap == "present" else "group_probe_denied"
        )
    assert clock[0] <= 0.5
    assert len([call for call in calls if call[0] == "wait"]) == 1
    assert not any(call[1] for call in calls[calls.index(("wait", 0.5)) + 1 :])


@pytest.mark.parametrize("failure", ["timeout", "oserror"])
def test_final_wait_failure_has_no_signal_or_second_wait_afterward(
    cleanup_model, monkeypatch, failure
):
    child, calls, _clock = cleanup_model

    def wait(*, timeout):
        calls.append(("wait", timeout))
        if failure == "timeout":
            raise subprocess.TimeoutExpired("fixture", timeout)
        raise OSError("fixture")

    monkeypatch.setattr(child, "wait", wait)
    result = process_module._terminate_owned_child(child, deadline=0.75, exit_observed=True)
    assert not result.complete and result.issues == ("reap_unconfirmed",)
    assert calls == [("signal", signal.SIGTERM), ("signal", signal.SIGKILL), ("wait", 0.5)]


@pytest.mark.parametrize("reaped_at", ["entry", "after_term"])
def test_known_reaped_identity_is_never_destructively_signalled_again(
    cleanup_model, monkeypatch, reaped_at
):
    child, calls, _clock = cleanup_model
    if reaped_at == "entry":
        child.returncode = 0
    else:

        def signal_and_reap(pid, sig):
            assert pid == child.pid and sig == signal.SIGTERM
            calls.append(("signal", sig))
            child.returncode = 0

        monkeypatch.setattr(process_module.os, "killpg", signal_and_reap)
    result = process_module._terminate_owned_child(child, deadline=0.75, exit_observed=True)
    assert not result.complete
    assert result.issues == ("reaped_before_" + ("term" if reaped_at == "entry" else "kill"),)
    assert calls == ([] if reaped_at == "entry" else [("signal", signal.SIGTERM)])


def test_cleanup_never_reuses_a_previous_grace_after_deadline(cleanup_model):
    child, calls, clock = cleanup_model
    clock[0] = 1.0
    result = process_module._terminate_owned_child(child, deadline=0.75, exit_observed=False)
    assert result.complete
    assert calls == [
        ("signal", signal.SIGTERM),
        ("signal", signal.SIGKILL),
        ("wait", 0),
        ("signal", 0),
    ]


@pytest.mark.parametrize("returncode", [9, -signal.SIGKILL])
def test_cleanup_preserves_the_actual_nonzero_exit_status(cleanup_model, monkeypatch, returncode):
    child, _calls, _clock = cleanup_model

    def wait(*, timeout):
        assert timeout == 0.5
        child.returncode = returncode
        return returncode

    monkeypatch.setattr(child, "wait", wait)
    result = process_module._terminate_owned_child(child, deadline=0.75, exit_observed=True)
    assert result.complete and result.returncode == returncode


@pytest.mark.parametrize("survivor", [False, True])
def test_zombie_leader_does_not_hide_surviving_group_members(cleanup_model, monkeypatch, survivor):
    child, calls, _clock = cleanup_model
    descendant_alive = True

    def group(pid, sig):
        nonlocal descendant_alive
        assert pid == child.pid
        calls.append(("signal", sig))
        if sig:
            assert child.returncode is None
            if sig == signal.SIGKILL:
                descendant_alive = survivor
        elif not descendant_alive:
            raise ProcessLookupError

    monkeypatch.setattr(process_module.os, "killpg", group)
    result = process_module._terminate_owned_child(child, deadline=0.75, exit_observed=True)
    assert result.reaped and result.complete == (not survivor)
    assert result.issues == (("group_still_present",) if survivor else ())
    assert [sig for name, sig in calls if name == "signal" and sig] == [
        signal.SIGTERM,
        signal.SIGKILL,
    ]


@pytest.mark.parametrize("boundary", ["deadline", "stop", "lease", "probe_exception"])
def test_stalled_actual_child_keeps_independent_control_and_is_reaped(case, boundary):
    started = time.monotonic()

    def stop():
        return boundary == "stop" and case[1].exists()

    def fence():
        if case[1].exists() and boundary == "probe_exception":
            raise RuntimeError("fixture-private-exception-must-not-escape")
        return not (boundary == "lease" and case[1].exists())

    outcome = run(
        case,
        "stall",
        stop=stop,
        fence=fence,
        limits=replace(case[2].limits, wall_seconds=2),
    )
    assert outcome.receipt is None
    assert (
        outcome.reason
        == {
            "deadline": "deadline",
            "stop": "stopped",
            "lease": "lease_lost",
            "probe_exception": "probe_failed",
        }[boundary]
    )
    assert time.monotonic() - started < 2.3
    assert_reaped(case[1])
    assert not tuple(case[0].glob("continuous-receipt-*"))


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("crash", "child_failed"),
        ("no_receipt", "process_failed"),
        ("symlink_receipt", "process_failed"),
        ("output", "output_limit"),
        ("oversized_receipt", "child_failed"),
        ("file_limit", "child_failed"),
        ("cpu", "child_failed"),
    ],
)
def test_actual_crash_output_receipt_and_cpu_fail_closed(case, mode, reason):
    limits = replace(case[2].limits, cpu_seconds=1, receipt_bytes=128, pipe_bytes=4096)
    outcome = run(case, mode, limits=limits)
    assert outcome.reason == reason and outcome.receipt is None
    assert_reaped(case[1])
    assert not tuple(case[0].glob(".continuous-operation-*"))


def test_stop_before_spawn_does_not_call_a_blocked_fence(case):
    def forbidden():
        raise AssertionError("stop must avoid fence work")

    outcome = run(case, stop=lambda: True, fence=forbidden)
    assert outcome.status == "stopped" and not case[1].exists()


def test_actual_memory_limit_leaves_no_receipt(case):
    result = run(case, "memory", limits=replace(case[2].limits, memory_bytes=128 * 1024 * 1024))
    assert result.reason in ("memory_limit", "child_failed") and result.receipt is None
    assert_reaped(case[1])


def test_one_operation_at_a_time_and_immediate_sequential_reuse(case):
    supervisor = case[3]
    assert supervisor._operation.acquire(blocking=False)
    try:
        assert run(case).reason == "operation_busy"
    finally:
        supervisor._operation.release()
    assert run(case).status == "completed"
    assert run(case).status == "completed"


def test_parent_signal_is_latched_and_original_handlers_are_restored(case):
    original = signal.getsignal(signal.SIGTERM)

    def sender():
        deadline = time.monotonic() + 2
        while not case[1].exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if case[1].exists():
            os.kill(os.getpid(), signal.SIGTERM)

    thread = threading.Thread(target=sender, daemon=True)
    thread.start()
    result = run(case, "stall")
    thread.join(timeout=0.1)
    assert result.reason == "stopped" and result.receipt is None
    assert signal.getsignal(signal.SIGTERM) is original
    assert_reaped(case[1])


def test_stuck_probe_cannot_hold_cleanup_or_allow_another_operation(case):
    blocked = threading.Event()
    started = time.monotonic()

    def fence():
        if case[1].exists():
            blocked.wait(5)
        return True

    try:
        outcome = run(case, "stall", fence=fence)
        assert outcome.reason == "probe_stalled" and outcome.receipt is None
        assert time.monotonic() - started < 2
        assert_reaped(case[1])
        assert run(case).reason == "probe_stalled"
    finally:
        blocked.set()


def test_public_api_always_uses_fixed_production_entrypoint(case, monkeypatch):
    calls = []

    def capture(*args, **kwargs):
        calls.append(kwargs["module"])
        return "fixture"

    monkeypatch.setattr(case[3], "_run", capture)
    case[3].run(
        case[2], lock_descriptor=3, stop_requested=lambda: False, fence_is_current=lambda: True
    )
    assert calls == ["apps.trader.continuous_simulation"]


@pytest.mark.parametrize(
    "changes",
    [
        {"wall_seconds": 121},
        {"wall_seconds": float("nan")},
        {"cpu_seconds": True},
        {"memory_bytes": 1024**3 + 1},
        {"receipt_bytes": 1024**2 + 1},
        {"pipe_bytes": 65537},
    ],
)
def test_reviewed_limit_ceilings_cannot_be_inflated(changes):
    with pytest.raises(ValueError):
        ContinuousProcessLimits(**changes)


def test_requests_reject_env_paths_and_reference_overflow(case):
    ref = ObjectRef("a" * 64, 1024 * 1024 + 1)
    for changes in (
        {"configuration_path": case[0] / ".env"},
        {"objects": (ref,) * 33},
        {"objects": (ref,) * 32},
        {"objects": ({"object_sha256": "a" * 64},)},
    ):
        with pytest.raises(ValueError):
            replace(case[2], **changes)


def test_parent_pipe_eof_stops_child_even_when_parent_pid_does_not_change(case):
    root, pid_file, request, _supervisor = case
    work = root / "direct"
    work.mkdir(mode=0o700)
    request_path = work / "request.json"
    request_path.write_bytes(_encode(replace(request, operation_id="pipe_eof")))
    request_path.chmod(0o600)
    death_read, death_write = os.pipe()
    with LocalInstanceGuard(root / "instance.lock") as guard:
        child = subprocess.Popen(
            (
                sys.executable,
                "-B",
                "-m",
                "tests.fixtures.continuous_process_child",
                "--worker",
                "--process-request",
                str(request_path),
                "--process-receipt",
                str(work / "receipt.json"),
                "--instance-lock-fd",
                str(guard.fileno()),
                "--parent-pid",
                str(os.getpid()),
                "--parent-death-fd",
                str(death_read),
            ),
            cwd=Path(__file__).resolve().parents[2],
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            pass_fds=(guard.fileno(), death_read),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        os.close(death_read)
        try:
            deadline = time.monotonic() + 2
            while not pid_file.exists() and time.monotonic() < deadline and child.poll() is None:
                time.sleep(0.01)
            assert pid_file.exists()
            os.close(death_write)
            death_write = -1
            assert child.wait(timeout=1) == 70
            assert not (work / "receipt.json").exists()
        finally:
            if death_write >= 0:
                os.close(death_write)
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=1)
    assert_reaped(pid_file)


def test_real_parent_crash_releases_inherited_lock_after_orphan_shutdown(case):
    root, pid_file, _request, _supervisor = case
    parent = subprocess.Popen(
        (sys.executable, "-B", "-m", "tests.fixtures.continuous_process_parent", str(root)),
        cwd=Path(__file__).resolve().parents[2],
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 3
        while not pid_file.exists() and time.monotonic() < deadline and parent.poll() is None:
            time.sleep(0.01)
        assert pid_file.exists()
        with pytest.raises(DuplicateRuntimeError), LocalInstanceGuard(root / "instance.lock"):
            pass
        parent.kill()
        parent.wait(timeout=1)
        deadline = time.monotonic() + 1.5
        while True:
            try:
                with LocalInstanceGuard(root / "instance.lock"):
                    break
            except DuplicateRuntimeError:
                assert time.monotonic() < deadline
                time.sleep(0.02)
        assert not tuple(root.glob("continuous-receipt-*"))
        assert not tuple(root.glob(".continuous-operation-*/receipt.json"))
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=1)
        if pid_file.exists() and sys.platform == "darwin":
            with pytest.raises(ProcessLookupError):
                # macOS reaps the orphan promptly; Linux may briefly retain a
                # zombie, so lock release above is the portable shutdown proof.
                os.kill(int(pid_file.read_text()), 0)


_REAL_CHILD_STATE_AND_RSS_PARSER = process_module._observe_child


@pytest.mark.parametrize("raw,rss", [(b"?E 0\n", 0), (b"?Es 524289\n", 536871936)])
def test_darwin_exiting_task_preserves_nonexit_and_full_rss(monkeypatch, raw, rss):
    monkeypatch.setattr(process_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        process_module.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout=raw),
    )
    assert process_module._observe_child(1234) == process_module._ChildObservation(False, rss)


@pytest.mark.parametrize(
    "platform,code,raw",
    [
        ("darwin", 0, b"? 0\n"),
        ("darwin", 0, b"?s 0\n"),
        ("darwin", 0, b"?Ex 0\n"),
        ("darwin", 0, b"?E\n"),
        ("darwin", 0, b"?E -1\n"),
        ("darwin", 0, b"?E x\n"),
        ("darwin", 0, b"?E 1\nZ 0\n"),
        ("darwin", 0, b"?E " + b"0" * 64),
        ("darwin", 1, b"?Es 0\n"),
        ("linux", 0, b"?Es 0\n"),
    ],
)
def test_exiting_transition_keeps_platform_rss_and_shape_rejection(
    monkeypatch, platform, code, raw
):
    monkeypatch.setattr(process_module.sys, "platform", platform)
    monkeypatch.setattr(
        process_module.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, code, stdout=raw),
    )
    with pytest.raises(ValueError, match="child observation unavailable"):
        process_module._observe_ps_child(1234)


def test_cleanup_exit_transition_requires_later_positive_z_before_reap(cleanup_model, monkeypatch):
    child, calls, clock = cleanup_model
    monkeypatch.setattr(process_module.sys, "platform", "darwin")
    monkeypatch.setattr(process_module, "_observe_child", _REAL_CHILD_STATE_AND_RSS_PARSER)
    responses = [b"?Es 0\n", b"Z 0\n"]

    def ps(command, **_kwargs):
        assert child.returncode is None
        raw = responses.pop(0)
        calls.append(("raw_ps", raw))
        return subprocess.CompletedProcess(command, 0, stdout=raw)

    monkeypatch.setattr(process_module.subprocess, "run", ps)
    result = process_module._terminate_owned_child(child, deadline=0.75, exit_observed=False)
    assert result.complete and not result.issues and not responses, result
    assert calls.index(("raw_ps", b"?Es 0\n")) < calls.index(("raw_ps", b"Z 0\n"))
    assert calls.index(("raw_ps", b"Z 0\n")) < calls.index(("signal", signal.SIGKILL))
    assert calls.index(("signal", signal.SIGKILL)) < next(
        i for i, c in enumerate(calls) if c[0] == "wait"
    )
    assert clock[0] <= 0.25


def test_exiting_task_still_triggers_original_supervisor_memory_limit(case, monkeypatch):
    monkeypatch.setattr(process_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        process_module.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout=b"?Es 524289\n"),
    )
    result = run(case, "stall")
    assert result.reason == "memory_limit" and result.receipt is None, result
    assert case[3]._cleanup is not None and case[3]._cleanup.complete
    assert_reaped(case[1])


@pytest.mark.parametrize("with_receipt", [False, True])
def test_cleanup_failure_after_supervision_discards_receipt_and_blocks_reuse(
    case, monkeypatch, with_receipt
):
    root, _pid, _request, supervisor = case
    receipt_path = root / "completed-before-cleanup.json"
    calls = []

    def supervise(*_args):
        calls.append("supervise")
        supervisor._cleanup_complete = False
        receipt = None
        if with_receipt:
            payload = b'{"fixture":true,"trading_authorized":false}'
            receipt_path.write_bytes(payload)
            receipt = process_module.ContinuousProcessReceiptRef(
                receipt_path, sha256(payload).hexdigest(), len(payload)
            )
        return process_module.ContinuousProcessOutcome("completed", "completed", receipt)

    monkeypatch.setattr(supervisor, "_supervise", supervise)
    outcome = run(case)
    assert outcome.status == "failed" and outcome.reason == "cleanup_incomplete"
    assert outcome.receipt is None and not receipt_path.exists()
    later = run(case)
    assert later.status == "failed" and later.reason == "cleanup_incomplete"
    assert later.receipt is None and calls == ["supervise"]


@pytest.fixture
def observation_deadline_model(case, monkeypatch):
    """Exercise supervisor decisions and local EOFs; cleanup is explicitly modeled."""
    from types import SimpleNamespace

    assert threading.current_thread() is threading.main_thread()
    original_monotonic = time.monotonic
    original_popen = subprocess.Popen
    original_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    clock = [0.0]
    calls = []
    streams = []
    for _ in range(2):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        streams.append(os.fdopen(read_fd, "rb"))
    child = SimpleNamespace(pid=1234, returncode=None, stdout=streams[0], stderr=streams[1])
    model = SimpleNamespace(selected_at=0.0, observed_at=0.0, error=None)

    class Selector:
        def __init__(self):
            self.keys = {}
            self.closed = False

        def register(self, stream, event):
            assert event == 1
            self.keys[stream] = SimpleNamespace(fd=stream.fileno(), fileobj=stream)

        def select(self, *, timeout):
            calls.append(("select", timeout))
            assert timeout == 0.05
            clock[0] = model.selected_at
            return [(key, 1) for key in self.keys.values()]

        def unregister(self, stream):
            del self.keys[stream]

        def get_map(self):
            return self.keys

        def close(self):
            self.closed = True

    selector = Selector()

    def launch(command, **kwargs):
        calls.append(("launch", command))
        assert "tests.fixtures.continuous_process_child" in command
        assert kwargs["start_new_session"] and kwargs["close_fds"]
        assert kwargs["stdout"] == subprocess.PIPE and kwargs["stderr"] == subprocess.PIPE
        return child

    def observe(pid, *, timeout):
        calls.append(("observe", pid, timeout))
        assert pid == child.pid and 0 < timeout <= 0.1
        assert model.error is not None, "deadline boundary must not start an observation"
        clock[0] = model.observed_at
        raise model.error

    def cleanup(owned, *, deadline, exit_observed):
        calls.append(("cleanup", owned, deadline, exit_observed))
        assert owned is child and owned.returncode is None
        return process_module._ChildCleanup(True, True, 0, ())

    # Replace only this module's references, never the shared stdlib objects.
    monkeypatch.setattr(process_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(
        process_module, "selectors", SimpleNamespace(DefaultSelector=lambda: selector, EVENT_READ=1)
    )
    monkeypatch.setattr(
        process_module,
        "subprocess",
        SimpleNamespace(
            Popen=launch,
            PIPE=subprocess.PIPE,
            DEVNULL=subprocess.DEVNULL,
            SubprocessError=subprocess.SubprocessError,
            TimeoutExpired=subprocess.TimeoutExpired,
        ),
    )
    monkeypatch.setattr(process_module, "_observe_child", observe)
    monkeypatch.setattr(process_module, "_terminate_owned_child", cleanup)

    def exercise(*, selected_at, observed_at, error, reason, observation_timeout):
        model.selected_at, model.observed_at, model.error = selected_at, observed_at, error
        result = run(case, "early_eof_stall", limits=replace(case[2].limits, wall_seconds=2))
        assert result.status == "failed" and result.reason == reason, result
        assert result.receipt is None
        assert [call[0] for call in calls] == (
            ["launch", "select", "cleanup"]
            if observation_timeout is None
            else ["launch", "select", "observe", "cleanup"]
        )
        if observation_timeout is not None:
            assert calls[2] == ("observe", child.pid, pytest.approx(observation_timeout))
        assert calls[-1] == ("cleanup", child, 2.0, False)
        assert selector.closed and not selector.get_map()
        assert all(stream.closed for stream in streams)
        assert case[3]._cleanup is not None and case[3]._cleanup.complete
        assert case[3]._cleanup.issues == ()
        assert case[3]._probe_thread is not None and not case[3]._probe_thread.is_alive()
        assert not case[1].exists()
        assert not tuple(case[0].glob(".continuous-operation-*"))
        assert not tuple(case[0].glob("continuous-receipt-*"))
        assert time.monotonic is original_monotonic and subprocess.Popen is original_popen
        assert all(signal.getsignal(sig) is handler for sig, handler in original_handlers.items())

    try:
        yield exercise
    finally:
        for stream in streams:
            stream.close()


@pytest.mark.parametrize("selected_at", [1.25, 1.5])
def test_deadline_after_selector_prevents_new_child_observation(
    observation_deadline_model, selected_at
):
    observation_deadline_model(
        selected_at=selected_at,
        observed_at=selected_at,
        error=None,
        reason="deadline",
        observation_timeout=None,
    )


@pytest.mark.parametrize(
    "selected_at,observed_at,reason,observation_timeout",
    [
        (0.1, 0.2, "child_observation_failed", 0.1),
        (1.2, 1.25, "deadline", 0.05),
        (1.2, 1.5, "deadline", 0.05),
    ],
)
def test_observation_timeout_uses_fresh_work_deadline(
    observation_deadline_model, selected_at, observed_at, reason, observation_timeout
):
    observation_deadline_model(
        selected_at=selected_at,
        observed_at=observed_at,
        error=subprocess.TimeoutExpired("modeled-observation", observation_timeout),
        reason=reason,
        observation_timeout=observation_timeout,
    )


@pytest.mark.parametrize("error_type", [ValueError, OSError, subprocess.SubprocessError])
def test_other_observation_failures_at_deadline_preserve_failure(
    observation_deadline_model, error_type
):
    observation_deadline_model(
        selected_at=1.2,
        observed_at=1.25,
        error=error_type("modeled observation failure"),
        reason="child_observation_failed",
        observation_timeout=0.05,
    )
