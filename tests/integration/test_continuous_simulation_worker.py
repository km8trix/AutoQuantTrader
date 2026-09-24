"""Fixed supervised child restores real halted signed history from SQLite.

The parent observes the actual child lease/control lifecycle through read-only
SQLite probes. Canonical history and integrity remain the child's responsibility.
"""

import json
from pathlib import Path

from apps.trader.continuous_process_lifecycle import SqlContinuousParentProbe
from packages.application.continuous_process import ContinuousProcessSupervisor
from packages.application.personal_runtime import LocalInstanceGuard
from tests.integration import test_continuous_simulation_factory as factory_fixture

configured = factory_fixture.configured


def test_fixed_worker_runs_real_halted_restore_and_restarts_with_identical_financial_history(
    configured,
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
        for _ in range(2):
            outcome = supervisor.run(
                request,
                lock_descriptor=lock.fileno(),
                stop_requested=lambda: False,
                lifecycle=SqlContinuousParentProbe(request),
            )
            assert outcome.status == "completed", outcome.reason
            assert outcome.receipt is not None
            payload = outcome.receipt.path.read_bytes()
            assert len(payload) == outcome.receipt.byte_count
            results.append(json.loads(payload))
    assert results[0] == results[1]
    assert results[0]["checkpoint_sha256"] == original.checkpoint.semantic_sha256
    assert results[0]["commit_sha256"] == original.receipt.commit.semantic_sha256
    assert results[0]["status"] == "restored"
    assert pair.counts() == counts
