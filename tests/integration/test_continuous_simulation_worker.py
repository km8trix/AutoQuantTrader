"""Fixed supervised child restores real halted signed history from SQLite.

The parent observes the actual child lease/control lifecycle through read-only
SQLite probes. Canonical history and integrity remain the child's responsibility.
"""

import json
from pathlib import Path

from apps.trader.continuous_process_lifecycle import SqlContinuousParentProbe
from packages.application import continuous_process as process_module
from packages.application.continuous_process import ContinuousProcessSupervisor
from packages.application.personal_runtime import LocalInstanceGuard
from tests.fixtures.continuous_process_observation import ChildObservationDiagnostic
from tests.integration import test_continuous_simulation_factory as factory_fixture

configured = factory_fixture.configured


def test_fixed_worker_runs_real_halted_restore_and_restarts_with_identical_financial_history(
    configured,
    monkeypatch,
):
    fixture, config = configured
    pair = fixture[0]
    factory_fixture.install_initial_signed_assignment(fixture)
    original = pair.account.restore(pair.base.scope)
    counts = pair.counts()
    factory_fixture.release(fixture)
    request = factory_fixture.request_for(fixture, config)
    private = Path(config.database_path).parent / "supervised"
    private.mkdir(mode=0o700)
    supervisor = ContinuousProcessSupervisor(artifact_directory=private)
    with LocalInstanceGuard(private / "instance.lock") as lock:
        results = []
        for iteration in range(1, 3):
            diagnostic = ChildObservationDiagnostic(process_module._observe_child)
            with monkeypatch.context() as observation_patch:
                observation_patch.setattr(process_module, "_observe_child", diagnostic.observe)
                outcome = supervisor.run(
                    request,
                    lock_descriptor=lock.fileno(),
                    stop_requested=lambda: False,
                    lifecycle=SqlContinuousParentProbe(request),
                )
            try:
                assert outcome.status == "completed", outcome.reason
            except AssertionError:
                # The original supervisor and its finally cleanup have returned;
                # only bounded static metadata is added to a failed assertion.
                print(
                    "AQT_CHILD_OBSERVATION_DIAGNOSTIC "
                    + json.dumps(diagnostic.summary(iteration=iteration), sort_keys=True)
                )
                raise
            assert outcome.receipt is not None
            payload = outcome.receipt.path.read_bytes()
            assert len(payload) == outcome.receipt.byte_count
            results.append(json.loads(payload))
    assert results[0] == results[1]
    assert results[0]["checkpoint_sha256"] == original.checkpoint.semantic_sha256
    assert results[0]["commit_sha256"] == original.receipt.commit.semantic_sha256
    assert results[0]["status"] == "restored"
    assert pair.counts() == counts
