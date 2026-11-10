"""First fresh child-process recovery; no retained-history or active-session claim.

Only the new tiny S3.11 fixture is constructed. The original supervisor chooses
the production child, sanitized environment, lifecycle and all resource limits.
No worker, probe, factory, authentication or clock method is replaced here.
"""

import json
import os
import stat
from contextlib import ExitStack
from hashlib import sha256

import pytest
import sqlalchemy as sa

from apps.trader.continuous_process_lifecycle import SqlContinuousParentProbe
from packages.application.continuous_process import (
    ContinuousProcessLimits,
    ContinuousProcessSupervisor,
)
from packages.application.personal_runtime import DuplicateRuntimeError, LocalInstanceGuard
from packages.persistence.account_coordinator import (
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.immutable import as_aware_utc
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
)
from tests.integration.test_continuous_synthetic_offline_configuration import (
    FINANCIAL_TABLES,
    _export,
    _facts,
    _objects,
    _release_setup,
    _request_file,
    _rows,
    _study,
)


def _require_receipt(study, request, result, artifacts):
    assert result.status == "completed", (result.status, result.reason)
    assert result.reason == "completed"
    reference = result.receipt
    assert reference is not None
    assert reference.path.parent == artifacts
    info = reference.path.lstat()
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.getuid() and info.st_nlink == 1
    assert 0 < info.st_size == reference.byte_count <= 16 * 1024
    payload = reference.path.read_bytes()
    assert len(payload) == reference.byte_count
    assert sha256(payload).hexdigest() == reference.object_sha256
    expected = {
        "schema": "continuous-offline-result/1",
        "operation_id": request.operation_id,
        "operation": "restore",
        "status": "restored",
        "account_id": study.genesis.scope.account_id,
        "sequence": 1,
        "commit_sha256": study.genesis.restored.receipt.commit.semantic_sha256,
        "checkpoint_sha256": study.genesis.restored.checkpoint.semantic_sha256,
        "assignment_generation": 1,
        "assignment_sha256": study.assignment.semantic_sha256,
    }
    assert json.loads(payload) == expected
    assert payload == json.dumps(expected, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    assert str(study.root).encode() not in payload
    assert tuple(artifacts.iterdir()) == (reference.path,)


def _require_quiescence(supervisor, probe, artifacts):
    assert supervisor._read_cleanup_complete()
    cleanup = supervisor._read_cleanup()
    assert cleanup is not None and cleanup.complete
    assert cleanup.reaped and cleanup.group_absent and cleanup.returncode == 0
    # Original Darwin cleanup may record denied zombie signals even when the
    # independent reap/group checks succeed; do not replace that contract.
    assert supervisor._probe_thread is not None and not supervisor._probe_thread.is_alive()
    assert probe._observed_exit and probe._phase == "released"
    assert probe._pid is not None and probe._pid != os.getpid()
    assert not tuple(artifacts.glob(".continuous-operation-*"))


def _require_store_preservation(
    study, configuration, before, lease_rows, release_rows, initial_head
):
    with ExitStack() as cleanup:
        account = create_database_engine(f"sqlite+pysqlite:///{study.paths['database_path']}")
        cleanup.callback(account.dispose)
        venue = create_database_engine(f"sqlite+pysqlite:///{study.paths['venue_database_path']}")
        cleanup.callback(venue.dispose)
        assert (
            _rows(account, FINANCIAL_TABLES),
            _rows(venue, JOURNAL_TABLES),
            _objects(study),
        ) == before
        after_leases, after_releases = _rows(
            account, (phase2_account_leases, phase2_account_lease_releases)
        )
        assert set(lease_rows).issubset(after_leases)
        assert set(release_rows).issubset(after_releases)
        assert len(after_leases) == len(lease_rows) + 1
        assert len(after_releases) == len(release_rows) + 1
        with account.connect() as connection:
            head = connection.execute(sa.select(phase2_account_lease_heads)).mappings().one()
            assert head["current_lease_sha256"] is None
            assert head["current_fencing_generation"] is None
            row = (
                connection.execute(
                    sa.select(phase2_account_leases).where(
                        phase2_account_leases.c.fencing_generation
                        == head["last_fencing_generation"]
                    )
                )
                .mappings()
                .one()
            )
            recovered = account_lease_from_row(row)
            release_row = (
                connection.execute(
                    sa.select(phase2_account_lease_releases).where(
                        phase2_account_lease_releases.c.lease_sha256 == recovered.semantic_sha256
                    )
                )
                .mappings()
                .one()
            )
            release = account_lease_release_from_row(release_row)
        assert recovered.account_id == study.genesis.scope.account_id
        assert recovered.fencing_generation == initial_head["last_fencing_generation"] + 1
        assert recovered.owner_id.startswith("offline-owner-")
        assert recovered.revision_number == 1
        assert recovered.policy_sha256 == configuration.lease_policy().semantic_sha256
        assert (
            recovered.expires_at - recovered.acquired_at == configuration.lease_policy().lease_ttl
        )
        assert recovered.acquired_at > study.request.command.expires_at
        assert release.fence == recovered.fence
        assert release.lease_sha256 == recovered.semantic_sha256
        assert release.policy_sha256 == recovered.policy_sha256
        assert recovered.acquired_at <= release.released_at < recovered.expires_at
        assert {**head, "updated_at": as_aware_utc(head["updated_at"])} == {
            "account_id": initial_head["account_id"],
            "last_fencing_generation": initial_head["last_fencing_generation"] + 1,
            "current_fencing_generation": None,
            "current_lease_sha256": None,
            "updated_at": release.released_at,
        }


def test_first_fresh_synthetic_child_restores_selected_halted_state(tmp_path):
    with _study(tmp_path) as study:
        configuration = _export(study)
        request = _request_file(study, configuration)
        configuration_bytes = request.configuration_path.read_bytes()
        assert request.limits == ContinuousProcessLimits()
        assert (
            request.limits.wall_seconds,
            request.limits.cpu_seconds,
            request.limits.memory_bytes,
            request.limits.receipt_bytes,
            request.limits.pipe_bytes,
        ) == (30.0, 30, 512 * 1024 * 1024, 1024 * 1024, 64 * 1024)
        assert (
            configuration.lease_ttl_microseconds,
            configuration.maximum_in_flight_microseconds,
            configuration.takeover_safety_microseconds,
        ) == (60_000_000, 5_000_000, 10_000_000)
        assert configuration.capture_evidence_class == "synthetic_fixture"
        assert configuration.clock_profile == "explicit_simulation_time_model"
        assert study.assignment.enabled_for_new_exposure is False
        assert study.assignment.live_authorized is False
        _release_setup(study)
        with study.ports["account_engine"].connect() as connection:
            initial_head = dict(
                connection.execute(sa.select(phase2_account_lease_heads)).mappings().one()
            )
        assert initial_head["account_id"] == study.genesis.scope.account_id
        assert initial_head["current_lease_sha256"] is None
        assert initial_head["current_fencing_generation"] is None
        facts = _facts(study)
        before, (lease_rows, release_rows) = facts[:3], facts[3]
        study.ports["account_engine"].dispose()
        study.ports["venue_engine"].dispose()

        artifacts = study.root / "process-artifacts"
        artifacts.mkdir(mode=0o700)
        lock_path = study.root / "first-fresh-child.lock"
        supervisor = ContinuousProcessSupervisor(artifact_directory=artifacts)
        probe = SqlContinuousParentProbe(request)
        errors = []
        lock_identity = None
        try:
            with LocalInstanceGuard(lock_path) as guard:
                info = os.fstat(guard.fileno())
                lock_identity = info.st_dev, info.st_ino
                with pytest.raises(DuplicateRuntimeError), LocalInstanceGuard(lock_path):
                    pytest.fail("second parent acquired the original held instance lock")
                result = supervisor.run(
                    request,
                    lock_descriptor=guard.fileno(),
                    stop_requested=lambda: False,
                    lifecycle=probe,
                )
                _require_receipt(study, request, result, artifacts)
        except BaseException as error:
            errors.append(error)
        finally:
            # Run every independent verification even if the original launch or
            # result assertion failed. Never acquire/renew/force-release a lease
            # to turn an interrupted child into a passing cleanup observation.
            for check in (
                lambda: _require_quiescence(supervisor, probe, artifacts),
                lambda: _require_store_preservation(
                    study, configuration, before, lease_rows, release_rows, initial_head
                ),
            ):
                try:
                    check()
                except BaseException as error:
                    errors.append(error)
            try:
                assert request.configuration_path.read_bytes() == configuration_bytes
            except BaseException as error:
                errors.append(error)
            try:
                with LocalInstanceGuard(lock_path) as guard:
                    info = os.fstat(guard.fileno())
                    assert (info.st_dev, info.st_ino) == lock_identity
            except BaseException as error:
                errors.append(error)
            try:
                # The original read-only probe uses NullPool. Dispose only once
                # its original thread has ended, never underneath a live probe.
                if probe._database is not None and (
                    supervisor._probe_thread is None or not supervisor._probe_thread.is_alive()
                ):
                    probe._database.engine.dispose()
            except BaseException as error:
                errors.append(error)
        if len(errors) == 1:
            raise errors[0]
        if errors:
            raise BaseExceptionGroup("fresh child recovery and verification failed", errors)
