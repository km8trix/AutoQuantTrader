"""Actual private SQLite rows and fixed worker lifecycle; synthetic financial inputs."""

import json
import os
import threading
import time
from dataclasses import replace
from hashlib import sha256
from uuid import uuid4

import pytest
import sqlalchemy as sa

from apps.trader.continuous_process_lifecycle import (
    ContinuousLifecycleError,
    SqlContinuousParentProbe,
    _bytes,
    _lease_fields,
)
from apps.trader.continuous_simulation_factory import _ActualClock
from packages.application import continuous_process as process_module
from packages.application.continuous_process import (
    ContinuousProcessLimits,
    ContinuousProcessStartup,
    ContinuousProcessSupervisor,
    _encode,
    _private_read,
    _private_write,
)
from packages.application.personal_runtime import LocalInstanceGuard
from packages.domain.personal_contracts import content_digest
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
    account_lease_from_row,
)
from packages.persistence.schema import phase5_operational_control_heads
from tests.integration.test_continuous_simulation_factory import (
    configured,  # noqa: F401
    release,
    request_for,
)
from tests.integration.test_runtime_owner_associations import install_initial_signed_assignment


@pytest.fixture
def ready_case(configured, tmp_path):  # noqa: F811
    fixture, config = configured
    install_initial_signed_assignment(fixture)
    release(fixture)
    request = request_for(fixture, config)
    directory = tmp_path / "private-lifecycle"
    directory.mkdir(mode=0o700)
    with LocalInstanceGuard(tmp_path / "parent.lock") as lock:
        info = os.fstat(lock.fileno())
        started = time.monotonic()
        startup = ContinuousProcessStartup(
            request,
            directory,
            uuid4().hex,
            os.getpid(),
            sha256(_encode(request)).hexdigest(),
            sha256(_private_read(request.configuration_path, 65536)).hexdigest(),
            info.st_dev,
            info.st_ino,
            started,
            started + 10,
            started + 20,
        )
        probe = SqlContinuousParentProbe(request)
        probe.prepare(startup)
        assert probe.observe(child_pid=None, child_exited=False) == "starting"
        owner = SqlAccountCoordinator(
            account_id=request.account_id,
            authority=SqlAccountCoordinatorAuthority(
                engine=fixture[0].base.engine, policy=config.lease_policy(), clock=_ActualClock()
            ),
        )
        # Transport fixture: actual new canonical lease and current process ID.
        # The separate fixed-worker tests supply the genuine Popen PID binding.
        nonce = uuid4().hex
        lease = owner.acquire(
            "offline-owner-" + content_digest((config.owner_id, os.getpid(), nonce))
        )
        rows = probe._database.capture()
        ready = {
            "schema": "continuous-lease-ready/1",
            "envelope_sha256": sha256(_bytes(probe._envelope)).hexdigest(),
            "child_pid": os.getpid(),
            "instance_nonce": nonce,
            "scope_sha256": fixture[0].base.scope.semantic_sha256,
            "lease": _lease_fields(lease),
            "control_sha256": rows.control["semantic_sha256"],
        }
        _private_write(directory / "lease-ready.json", _bytes(ready))
        yield probe, owner, lease, startup, ready, fixture, config
        probe._database.engine.dispose()


def observe(probe, *, exited=False):
    return probe.observe(child_pid=os.getpid(), child_exited=exited)


def result_for(probe):
    return json.dumps(
        {
            "schema": "continuous-offline-result/1",
            "account_id": probe.request.account_id,
            "operation_id": probe.request.operation_id,
            "operation": "restore",
            "status": "restored",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def begin_close(probe, startup, ready):
    payload = result_for(probe)
    frame = {
        "schema": "continuous-result-ready/1",
        "ready_sha256": sha256(_bytes(ready)).hexdigest(),
        "result_sha256": sha256(payload).hexdigest(),
        "result_bytes": len(payload),
    }
    _private_write(startup.directory / "result-ready.json", _bytes(frame))
    return payload, frame


def complete_close(startup, ready, released, payload):
    frame = {
        "schema": "continuous-lease-released/1",
        "ready_sha256": sha256(_bytes(ready)).hexdigest(),
        "release_id": released.release_id,
        "release_sha256": released.semantic_sha256,
        "released_at": released.released_at.isoformat(),
        "result_sha256": sha256(payload).hexdigest(),
        "result_bytes": len(payload),
    }
    _private_write(startup.directory / "lease-released.json", _bytes(frame))


def test_parent_probe_reads_exact_live_and_released_rows_without_any_sql_write(ready_case):
    probe, owner, lease, startup, ready, *_ = ready_case
    statements = []
    sa.event.listen(
        probe._database.engine,
        "before_cursor_execute",
        lambda _c, _cu, text, *_a: statements.append(text),
    )
    before = probe._database.capture()
    assert observe(probe) == "leased"
    assert observe(probe) == "leased"
    assert probe._database.capture() == before
    payload, _frame = begin_close(probe, startup, ready)
    assert observe(probe) == "closing"
    released = owner.release(lease.fence)
    assert observe(probe) == "closing"  # deliberate release → terminal-file gap
    complete_close(startup, ready, released, payload)
    assert observe(probe) == "released"
    with pytest.raises(ContinuousLifecycleError):
        probe.require_result(payload)  # zero child exit was not yet observed
    assert observe(probe, exited=True) == "released"
    probe.require_result(payload)
    assert all(
        text.lstrip().upper().startswith(("SELECT", "BEGIN", "PRAGMA QUERY_ONLY"))
        for text in statements
    )
    assert not any("UPDATE " in text.upper() or "INSERT " in text.upper() for text in statements)


@pytest.mark.parametrize(
    "fault", ["pid", "nonce", "generation", "control", "early_release", "takeover"]
)
def test_original_process_lease_and_all_halted_control_fields_fail_closed(ready_case, fault):
    probe, owner, lease, startup, ready, fixture, _config = ready_case
    if fault in ("pid", "nonce", "generation"):
        changed = dict(ready)
        if fault == "pid":
            changed["child_pid"] += 1
        elif fault == "nonce":
            changed["instance_nonce"] = "0" * 32
        else:
            changed["lease"] = ready["lease"] | {"generation": lease.fencing_generation + 1}
        path = startup.directory / "lease-ready.json"
        path.unlink()
        _private_write(path, _bytes(changed))
    else:
        assert observe(probe) == "leased"
        if fault == "control":
            with fixture[0].base.engine.begin() as connection:
                connection.execute(
                    sa.update(phase5_operational_control_heads).values(canonical_payload="{}")
                )
        else:
            owner.release(lease.fence)
            if fault == "takeover":
                owner.acquire("different-actual-process-owner")
    with pytest.raises(ContinuousLifecycleError):
        observe(probe)


@pytest.mark.parametrize("fault", ["result_hash", "missing_release", "closing_timeout"])
def test_terminal_claim_cannot_replace_actual_release_and_bound_result(
    ready_case, monkeypatch, fault
):
    probe, owner, lease, startup, ready, *_ = ready_case
    assert observe(probe) == "leased"
    payload, _frame = begin_close(probe, startup, ready)
    assert observe(probe) == "closing"
    if fault == "closing_timeout":
        monkeypatch.setattr(
            "apps.trader.continuous_process_lifecycle.time.monotonic",
            lambda: probe._closing_deadline,
        )
    elif fault == "missing_release":
        # No actual release: even a terminal-looking transport record cannot qualify.
        _private_write(startup.directory / "lease-released.json", b"{}")
    else:
        released = owner.release(lease.fence)
        complete_close(startup, ready, released, payload + b" ")
    with pytest.raises(ContinuousLifecycleError):
        observe(probe)


@pytest.mark.parametrize("publish_before_sql", [False, True])
def test_complete_result_frames_cannot_be_paired_with_older_sql_snapshot(
    ready_case, monkeypatch, publish_before_sql
):
    probe, owner, lease, startup, ready, *_ = ready_case
    assert observe(probe) == "leased"
    original = probe._database.capture
    changed = False
    payload = result_for(probe)

    def capture():
        nonlocal changed
        if changed:
            return original()
        changed = True
        prior = None if publish_before_sql else original()
        begin_close(probe, startup, ready)
        released = owner.release(lease.fence)
        complete_close(startup, ready, released, payload)
        return original() if publish_before_sql else prior

    monkeypatch.setattr(probe._database, "capture", capture)
    assert observe(probe) in ("leased", "released")
    assert observe(probe, exited=True) == "released"
    probe.require_result(payload)


@pytest.mark.parametrize("fault", ["stop", "ready_pid", "result", "early_release", "takeover"])
def test_fixed_actual_child_parent_faults_never_accept_a_receipt(
    configured,  # noqa: F811
    tmp_path,
    monkeypatch,
    fault,
):
    fixture, config = configured
    install_initial_signed_assignment(fixture)
    release(fixture)
    request = replace(request_for(fixture, config), limits=ContinuousProcessLimits(wall_seconds=30))
    probe = SqlContinuousParentProbe(request)
    original = probe.observe
    stopped = False
    acted = False
    observed = []

    def checked(**kwargs):
        nonlocal stopped, acted
        if fault == "ready_pid" and probe._startup is not None:
            path = probe._startup.directory / "lease-ready.json"
            if path.exists() and probe._ready is None:
                value = json.loads(path.read_bytes())
                value["child_pid"] += 1
                path.unlink()
                _private_write(path, _bytes(value))
        phase = original(**kwargs)
        observed.append(phase)
        if phase == "leased" and fault == "stop":
            stopped = True
        if phase == "leased" and not acted and fault in ("early_release", "takeover"):
            # Separate test fault actor mutates the real DB; the production
            # parent probe remains SQL read-only throughout this operation.
            acted = True
            actor = SqlAccountCoordinator(
                account_id=request.account_id,
                authority=SqlAccountCoordinatorAuthority(
                    engine=fixture[0].base.engine,
                    policy=config.lease_policy(),
                    clock=_ActualClock(),
                ),
            )
            actual = account_lease_from_row(probe._original_lease)
            actor.release(actual.fence)
            if fault == "takeover":
                actor.acquire("different-test-child-owner")
        if phase == "released" and kwargs["child_exited"] and fault == "result":
            path = probe._startup.directory / "receipt.json"
            path.write_bytes(path.read_bytes() + b" ")
        return phase

    monkeypatch.setattr(probe, "observe", checked)
    tmp_path.chmod(0o700)
    supervisor = ContinuousProcessSupervisor(artifact_directory=tmp_path)
    with LocalInstanceGuard(tmp_path / "actual-parent.lock") as lock:
        result = supervisor.run(
            request, lock_descriptor=lock.fileno(), stop_requested=lambda: stopped, lifecycle=probe
        )
    assert result.receipt is None and result.status != "completed"
    if fault == "stop":
        assert "leased" in observed and result.status == "stopped"
    if fault in ("early_release", "takeover"):
        assert acted
    assert supervisor._probe_thread is not None and not supervisor._probe_thread.is_alive()
    assert not tuple(tmp_path.glob(".continuous-operation-*"))


def test_fixed_child_requires_probe_sampled_after_exit_before_accepting_result(
    configured,  # noqa: F811
    tmp_path,
    monkeypatch,
):
    fixture, config = configured
    install_initial_signed_assignment(fixture)
    release(fixture)
    request = request_for(fixture, config)
    probe = SqlContinuousParentProbe(request)
    original_launch = process_module.subprocess.Popen
    original_child_observe = process_module._observe_child
    original_observe = probe.observe
    original_require_result = probe.require_result
    zombie_seen = threading.Event()
    pre_exit_sample_started = threading.Event()
    owned_children = []
    waits = []
    delayed_observation = False
    post_exit_sample = False

    def launch(*args, **kwargs):
        child = original_launch(*args, **kwargs)
        if "apps.trader.continuous_simulation" in args[0]:
            owned_children.append(child)
            original_wait = child.wait

            def forbidden_poll():
                raise AssertionError("neither supervisor thread may reap through poll")

            def wait(*, timeout):
                waits.append(timeout)
                return original_wait(timeout=timeout)

            monkeypatch.setattr(child, "poll", forbidden_poll)
            monkeypatch.setattr(child, "wait", wait)
        return child

    def observe_child(pid, **kwargs):
        assert threading.current_thread() is threading.main_thread()
        assert owned_children and owned_children[0].returncode is None
        observation = original_child_observe(pid, **kwargs)
        if observation.exited and not zombie_seen.is_set():
            # Hold the main thread's real, non-reaping observation just long
            # enough for the SQL thread to sample the still-false exit latch.
            zombie_seen.set()
            assert pre_exit_sample_started.wait(0.2)
        return observation

    def observe_after_delay(**kwargs):
        nonlocal delayed_observation, post_exit_sample
        if zombie_seen.is_set() and not kwargs["child_exited"]:
            pre_exit_sample_started.set()
            time.sleep(0.1)  # this false sample finishes after main freezes exit
            delayed_observation = True
        if kwargs["child_exited"]:
            post_exit_sample = True
        return original_observe(**kwargs)

    def require_result(payload):
        assert delayed_observation and post_exit_sample
        assert supervisor._cleanup is not None and supervisor._cleanup.complete
        assert owned_children[0].returncode == 0 and len(waits) == 1
        return original_require_result(payload)

    monkeypatch.setattr(process_module.subprocess, "Popen", launch)
    monkeypatch.setattr(process_module, "_observe_child", observe_child)
    monkeypatch.setattr(probe, "observe", observe_after_delay)
    monkeypatch.setattr(probe, "require_result", require_result)
    tmp_path.chmod(0o700)
    supervisor = ContinuousProcessSupervisor(artifact_directory=tmp_path)
    with LocalInstanceGuard(tmp_path / "actual-exit-parent.lock") as lock:
        result = supervisor.run(
            request, lock_descriptor=lock.fileno(), stop_requested=lambda: False, lifecycle=probe
        )
    assert pre_exit_sample_started.is_set() and delayed_observation and post_exit_sample
    assert result.status == "completed", result.reason
    assert probe._observed_exit
    assert supervisor._probe_thread is not None and not supervisor._probe_thread.is_alive()
    assert not tuple(tmp_path.glob(".continuous-operation-*"))
