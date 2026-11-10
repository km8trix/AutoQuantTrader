"""Fresh HALTED synthetic CLI recovery through the original supervised worker.

The sole observation wrapper forwards the exact call to the original public
supervisor once and retains its real result/probe for independent assertions.
No outcome, worker, native process, clock, factory or probe method is replaced.
"""

import json
import os
from types import SimpleNamespace

import pytest
import sqlalchemy as sa

from apps.trader.continuous_recovery import main
from packages.application.continuous_process import (
    ContinuousProcessLimits,
    ContinuousProcessSupervisor,
)
from packages.application.personal_runtime import LocalInstanceGuard
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignment_heads
from packages.persistence.schema import phase2_account_lease_heads
from tests.integration.test_continuous_synthetic_offline_configuration import (
    _export,
    _facts,
    _release_setup,
    _request_file,
    _study,
)
from tests.integration.test_continuous_synthetic_process_recovery import (
    _require_quiescence,
    _require_receipt,
    _require_store_preservation,
)


@pytest.fixture
def observed_supervision(monkeypatch):
    original = ContinuousProcessSupervisor.run
    calls = []

    def observe(supervisor, *args, **kwargs):
        info = os.fstat(kwargs["lock_descriptor"])
        call = SimpleNamespace(
            supervisor=supervisor,
            args=args,
            kwargs=kwargs,
            outcome=None,
            lock_identity=(info.st_dev, info.st_ino),
        )
        calls.append(call)
        # Observation only: original method, exact original arguments, one call.
        call.outcome = original(supervisor, *args, **kwargs)
        return call.outcome

    monkeypatch.setattr(ContinuousProcessSupervisor, "run", observe)
    return calls


def _prepare(study):
    configuration = _export(study)
    request = _request_file(study, configuration)
    _release_setup(study)
    with study.ports["account_engine"].connect() as connection:
        initial_head = dict(
            connection.execute(sa.select(phase2_account_lease_heads)).mappings().one()
        )
    assert initial_head["current_lease_sha256"] is None
    assert initial_head["current_fencing_generation"] is None
    artifacts = study.root / "cli-process-artifacts"
    artifacts.mkdir(mode=0o700)
    lock = study.root / "cli-parent.lock"
    arguments = [
        "--configuration",
        str(request.configuration_path),
        "--account-id",
        request.account_id,
        "--operation-id",
        request.operation_id,
        "--instance-lock",
        str(lock),
        "--artifact-directory",
        str(artifacts),
    ]
    return SimpleNamespace(
        configuration=configuration,
        request=request,
        initial_head=initial_head,
        artifacts=artifacts,
        lock=lock,
        arguments=arguments,
        configuration_bytes=request.configuration_path.read_bytes(),
    )


def _cold(study):
    facts = _facts(study)
    study.ports["account_engine"].dispose()
    study.ports["venue_engine"].dispose()
    return facts


def _summary(capsys, *, status, reason, cleanup_complete=None):
    captured = capsys.readouterr()
    assert captured.err == ""
    expected = {
        "schema": "continuous-synthetic-recovery-summary/1",
        "status": status,
        "reason": reason,
        "operation": "restore",
        "trading_authority": False,
    }
    if cleanup_complete is not None:
        expected["cleanup_complete"] = cleanup_complete
    assert captured.out == json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
    assert "receipt" not in captured.out and "account_id" not in captured.out
    return captured.out


def _actual_call(calls, case):
    assert len(calls) == 1
    call = calls[0]
    assert len(call.args) == 1
    actual = call.args[0]
    assert actual == case.request
    assert actual.limits == ContinuousProcessLimits()
    assert (
        actual.limits.wall_seconds,
        actual.limits.cpu_seconds,
        actual.limits.memory_bytes,
        actual.limits.receipt_bytes,
        actual.limits.pipe_bytes,
    ) == (30.0, 30, 512 * 1024 * 1024, 1024 * 1024, 64 * 1024)
    assert set(call.kwargs) == {"lock_descriptor", "stop_requested", "lifecycle"}
    assert call.kwargs["lifecycle"].request is actual
    assert call.outcome is not None
    info = case.lock.lstat()
    assert (info.st_dev, info.st_ino) == call.lock_identity
    return call


def _require_final_facts(study, case, facts):
    before, (leases, releases) = facts[:3], facts[3]
    _require_store_preservation(
        study, case.configuration, before, leases, releases, case.initial_head
    )
    assert case.request.configuration_path.read_bytes() == case.configuration_bytes


def _require_lock_released(case, identity):
    with LocalInstanceGuard(case.lock) as guard:
        info = os.fstat(guard.fileno())
        assert (info.st_dev, info.st_ino) == identity


def _run_and_verify(checks, primary):
    errors = [primary] if primary is not None else []
    for check in checks:
        try:
            check()
        except BaseException as error:
            errors.append(error)
    if len(errors) == 1:
        raise errors[0]
    if errors:
        raise BaseExceptionGroup("fresh synthetic CLI and independent verification failed", errors)


def test_cli_restores_one_new_tiny_selected_halted_synthetic_graph(
    tmp_path, observed_supervision, capsys
):
    with _study(tmp_path) as study:
        case = _prepare(study)
        facts = _cold(study)
        primary = None
        identity = None
        try:
            assert main(case.arguments) == 0
            call = _actual_call(observed_supervision, case)
            identity = call.lock_identity
            _summary(capsys, status="completed", reason="completed", cleanup_complete=True)
            _require_receipt(study, call.args[0], call.outcome, case.artifacts)
        except BaseException as error:
            primary = error
        finally:

            def quiescence():
                call = _actual_call(observed_supervision, case)
                _require_quiescence(call.supervisor, call.kwargs["lifecycle"], case.artifacts)

            _run_and_verify(
                (
                    quiescence,
                    lambda: _require_final_facts(study, case, facts),
                    lambda: _require_lock_released(case, identity),
                ),
                primary,
            )


def test_cli_duplicate_parent_denial_does_not_launch_or_change_fresh_stores(
    tmp_path, observed_supervision, capsys
):
    with _study(tmp_path) as study:
        case = _prepare(study)
        facts = _cold(study)
        with LocalInstanceGuard(case.lock) as guard:
            info = os.fstat(guard.fileno())
            identity = info.st_dev, info.st_ino
            assert main(case.arguments) == 2
            _summary(capsys, status="failed", reason="instance_busy")
            assert observed_supervision == []
            assert _facts(study) == facts
            with study.ports["account_engine"].connect() as connection:
                assert (
                    dict(connection.execute(sa.select(phase2_account_lease_heads)).mappings().one())
                    == case.initial_head
                )
            assert case.request.configuration_path.read_bytes() == case.configuration_bytes
            assert not tuple(case.artifacts.iterdir())
        _require_lock_released(case, identity)


def test_cli_original_child_failure_after_acquisition_releases_without_repair(
    tmp_path, observed_supervision, capsys
):
    with _study(tmp_path) as study:
        case = _prepare(study)
        # Existing direct-factory adverse, applied only to this newly constructed
        # disposable fixture. Keep the damaged state; never repair it to pass.
        with study.ports["account_engine"].begin() as connection:
            changed = connection.execute(
                daily_runtime_assignment_heads.delete().where(
                    daily_runtime_assignment_heads.c.account_id == study.genesis.scope.account_id
                )
            )
            assert changed.rowcount == 1
        facts = _cold(study)
        primary = None
        identity = None
        try:
            assert main(case.arguments) == 3
            call = _actual_call(observed_supervision, case)
            assert call.outcome.status == "failed" and call.outcome.receipt is None
            assert call.outcome.reason in {"child_failed", "probe_failed", "process_failed"}
            _summary(capsys, status="failed", reason=call.outcome.reason, cleanup_complete=True)
            identity = call.lock_identity
        except BaseException as error:
            primary = error
        finally:

            def quiescence():
                call = _actual_call(observed_supervision, case)
                cleanup = call.supervisor._read_cleanup()
                assert call.supervisor._read_cleanup_complete()
                assert cleanup is not None and cleanup.complete
                assert cleanup.reaped and cleanup.group_absent and cleanup.returncode != 0
                assert call.supervisor._probe_thread is not None
                assert not call.supervisor._probe_thread.is_alive()
                assert call.kwargs["lifecycle"]._pid is not None
                assert call.kwargs["lifecycle"]._pid != os.getpid()
                assert not tuple(case.artifacts.iterdir())

            _run_and_verify(
                (
                    quiescence,
                    lambda: _require_final_facts(study, case, facts),
                    lambda: _require_lock_released(case, identity),
                ),
                primary,
            )
