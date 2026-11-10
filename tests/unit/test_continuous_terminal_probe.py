"""Terminal supervision schedules with modeled child/cleanup; no process is spawned."""

import os
import queue
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.application import continuous_process as process
from packages.application.personal_runtime import LocalInstanceGuard


@pytest.fixture
def terminal_model(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    main = threading.current_thread()
    progress = threading.Event()
    release = threading.Event()
    pre_exit_started = threading.Event()
    release_pre_exit = threading.Event()
    terminal_started = threading.Event()
    model = SimpleNamespace(
        mode="normal",
        phase="released",
        eof_delay=0,
        clock_offset=0.0,
        exited=False,
        terminal_received=False,
        eof_delayed=False,
        pre_exit_finished=False,
        post_exit_calls=0,
        calls=[],
        threads=[],
        streams=[],
    )
    original_monotonic = time.monotonic

    class ProbeThread(threading.Thread):
        def __init__(self, *args, **kwargs):
            original = kwargs["target"]

            def target():
                try:
                    original()
                finally:
                    model.calls.append("probe_finished")
                    progress.set()

            kwargs["target"] = target
            super().__init__(*args, **kwargs)
            model.threads.append(self)

    class HandoffQueue(queue.Queue):
        def get_nowait(self):
            result = super().get_nowait()
            if threading.current_thread() is main:
                if result[3]:
                    model.terminal_received = True
                    model.calls.append("parent_received_terminal")
                    # Permit the producer to run before this handoff completes.
                    # Old behavior enters a redundant callback; terminal behavior
                    # ends its thread. No timeout/age constant is changed.
                    assert progress.wait(1), "terminal handoff did not finish"
                elif model.mode == "pre_exit_only" and result[2] == "released":
                    assert terminal_started.wait(1)
                    model.clock_offset += 0.6
            return result

    class Lifecycle:
        def prepare(self, startup):
            model.calls.append("prepare")

        def observe(self, *, child_pid, child_exited):
            if child_exited:
                model.post_exit_calls += 1
                model.calls.append("terminal_observe")
                terminal_started.set()
                if model.mode in ("blocked", "pre_exit_only") or model.post_exit_calls == 2:
                    progress.set()
                    assert release.wait(2), "modeled callback cleanup did not finish"
                if model.mode == "error":
                    raise ValueError("private callback detail")
                return model.phase
            if child_pid is not None and model.mode in ("pre_exit", "pre_exit_only"):
                pre_exit_started.set()
                assert release_pre_exit.wait(1)
                model.pre_exit_finished = True
                model.calls.append("pre_exit_observation_finished")
                return "released"
            return "starting" if child_pid is None else "leased"

        def require_result(self, payload):
            model.calls.append("require_result")
            assert model.post_exit_calls == 1
            assert payload == b'{"fixture":true}'

    for _ in range(2):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        model.streams.append(os.fdopen(read_fd, "rb"))
    child = SimpleNamespace(
        pid=1234, returncode=None, stdout=model.streams[0], stderr=model.streams[1]
    )

    class Selector:
        def __init__(self):
            self.keys = {}

        def register(self, stream, event):
            assert event == 1
            self.keys[stream] = SimpleNamespace(fd=stream.fileno(), fileobj=stream)

        def select(self, *, timeout):
            if not model.exited and model.mode in ("pre_exit", "pre_exit_only"):
                assert pre_exit_started.wait(1)
            if model.eof_delay:
                if not model.terminal_received:
                    time.sleep(min(timeout, 0.005))
                    return []
                if not model.eof_delayed:
                    model.clock_offset += model.eof_delay
                    model.eof_delayed = True
                    return []
            if not self.keys:
                time.sleep(min(timeout, 0.005))
            return [(key, 1) for key in self.keys.values()]

        def unregister(self, stream):
            del self.keys[stream]

        def get_map(self):
            return self.keys

        def close(self):
            self.keys.clear()

    def launch(command, **kwargs):
        model.calls.append("modeled_launch")
        assert process._PRODUCTION_MODULE in command
        assert kwargs["start_new_session"] and kwargs["close_fds"]
        receipt = Path(command[command.index("--process-receipt") + 1])
        process._private_write(receipt, b'{"fixture":true}')
        return child

    def observe_child(pid, *, timeout):
        assert pid == child.pid and 0 < timeout <= 0.1
        model.exited = True
        return process._ChildObservation(True, 0)

    def cleanup(owned, *, deadline, exit_observed):
        assert owned is child and exit_observed
        model.calls.append("modeled_cleanup")
        release_pre_exit.set()
        return process._ChildCleanup(True, True, 0, ())

    monkeypatch.setattr(
        process,
        "threading",
        SimpleNamespace(
            Lock=threading.Lock,
            Event=threading.Event,
            Thread=ProbeThread,
            current_thread=threading.current_thread,
            main_thread=threading.main_thread,
        ),
    )
    monkeypatch.setattr(
        process, "queue", SimpleNamespace(Queue=HandoffQueue, Empty=queue.Empty, Full=queue.Full)
    )
    monkeypatch.setattr(
        process,
        "subprocess",
        SimpleNamespace(
            Popen=launch,
            PIPE=subprocess.PIPE,
            DEVNULL=subprocess.DEVNULL,
            SubprocessError=subprocess.SubprocessError,
            TimeoutExpired=subprocess.TimeoutExpired,
        ),
    )
    monkeypatch.setattr(
        process, "selectors", SimpleNamespace(DefaultSelector=Selector, EVENT_READ=1)
    )
    monkeypatch.setattr(
        process,
        "time",
        SimpleNamespace(monotonic=lambda: original_monotonic() + model.clock_offset),
    )
    monkeypatch.setattr(process, "_observe_child", observe_child)
    monkeypatch.setattr(process, "_terminate_owned_child", cleanup)
    config = tmp_path / "configuration.json"
    process._private_write(config, b"{}")
    request = process.ContinuousProcessRequest(
        "fixture-account",
        "fixture-operation",
        config,
        limits=process.ContinuousProcessLimits(wall_seconds=4, cpu_seconds=3),
    )
    supervisor = process.ContinuousProcessSupervisor(artifact_directory=tmp_path)

    def run():
        with LocalInstanceGuard(tmp_path / "instance.lock") as guard:
            return supervisor.run(
                request,
                lock_descriptor=guard.fileno(),
                stop_requested=lambda: model.mode == "stop" and model.exited,
                lifecycle=Lifecycle(),
            )

    model.run = run
    model.supervisor = supervisor
    try:
        yield model
    finally:
        release.set()
        release_pre_exit.set()
        for thread in model.threads:
            thread.join(1)
            assert not thread.is_alive()
        assert all(stream.closed for stream in model.streams)
        assert not tuple(tmp_path.glob(".continuous-operation-*"))


def test_post_exit_sample_ends_producer_before_terminal_handoff_join(terminal_model):
    model = terminal_model
    result = model.run()
    assert result.status == "completed" and result.receipt is not None, result.reason
    assert model.post_exit_calls == 1
    assert model.calls.index("probe_finished") < model.calls.index("require_result")
    assert model.supervisor._cleanup.complete
    assert not model.supervisor._probe_thread.is_alive()


@pytest.mark.parametrize(("delay", "reason"), [(0.1, "completed"), (0.6, "probe_stalled")])
def test_eof_delay_does_not_renew_terminal_observation(terminal_model, delay, reason):
    model = terminal_model
    model.eof_delay = delay
    result = model.run()
    assert result.reason == reason
    assert (result.receipt is not None) is (reason == "completed")
    assert model.post_exit_calls == 1
    assert process._PROBE_AGE == 0.5


@pytest.mark.parametrize(("mode", "reason"), [("stop", "stopped"), ("error", "probe_failed")])
def test_terminal_stop_or_callback_error_precedes_receipt(terminal_model, mode, reason):
    model = terminal_model
    model.mode = mode
    result = model.run()
    assert result.reason == reason and result.receipt is None
    assert "require_result" not in model.calls


@pytest.mark.parametrize(
    ("phase", "reason"),
    [
        ("released", "completed"),
        ("closing", "lifecycle_incomplete"),
        ("leased", "lifecycle_incomplete"),
        ("starting", "lifecycle_incomplete"),
        ("invalid", "probe_failed"),
    ],
)
def test_terminal_callback_must_return_released_lifecycle(terminal_model, phase, reason):
    model = terminal_model
    model.phase = phase
    result = model.run()
    assert result.reason == reason
    assert (result.receipt is not None) is (reason == "completed")


@pytest.mark.parametrize("mode", ["pre_exit", "pre_exit_only"])
def test_pre_exit_started_callback_cannot_qualify_child_exit(terminal_model, mode):
    model = terminal_model
    model.mode = mode
    result = model.run()
    assert model.pre_exit_finished
    assert result.reason == ("completed" if mode == "pre_exit" else "probe_stalled")
    assert (result.receipt is not None) is (mode == "pre_exit")
    assert model.calls.index("pre_exit_observation_finished") < model.calls.index(
        "terminal_observe"
    )


def test_blocked_terminal_callback_keeps_age_and_sequential_reuse_denial(terminal_model):
    model = terminal_model
    model.mode = "blocked"
    result = model.run()
    assert result.reason == "probe_stalled" and result.receipt is None
    before = model.calls[:]
    assert model.run().reason == "probe_stalled"
    assert model.calls == before
    assert model.supervisor._cleanup.complete
