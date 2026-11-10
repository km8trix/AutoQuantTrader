"""Existing read owners distinguish committed installation from physical rollback.

Each command fixture completely exits before an explicitly opened L/G/K lifetime.
Only original-code observations copy correlation data; no new app port or auth
model, financial reader, reducer, lease policy or result substitution is added.
"""

import os
import sys
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import Engine
from sqlalchemy.pool import NullPool

from apps.api.configured_readiness_reads import configured_readiness_reads
from apps.api.readiness_read_store import ReadinessReadStore, ReadinessReadStoreStatus
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from apps.trader.continuous_readiness_owner import (
    ContinuousReadinessOwner,
    ReadinessOwnerLimits,
    _ReadinessRuntime,
)
from apps.trader.continuous_simulation_factory import ContinuousSimulationFactory
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.personal_runtime import LocalInstanceGuard
from packages.domain.account_coordinator import AccountLease, AccountLeaseRelease
from packages.domain.continuous_selection_contracts import ContinuousSelectionSnapshot
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.continuous_selection_read_model import SqlContinuousSelectionReadModel
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_assignment_heads,
    daily_runtime_assignments,
)
from packages.persistence.database import verify_operational_schema
from packages.persistence.runtime_assignment_publication import SqlRuntimeAssignmentPublication
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from packages.persistence.runtime_owner_commands import SqlRuntimeOwnerCommands
from tests.integration import test_continuous_synthetic_initial_selection_installation as original_g
from tests.integration import (
    test_continuous_synthetic_initial_selection_installation_owner as original_h,
)
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot


def _receipt(value):
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


def _association_values(value):
    """Fixed native observation after original successful ownership validation."""
    source, command = value.dependencies, value.request.record.command
    auth, heads = value.request.record.authentication, command.expected_heads
    return (
        (source.scope.account_id, source.scope.account_binding_sha256, source.scope.stream_id),
        _receipt(value.request.read.receipt),
        (
            source.proposed.semantic_sha256,
            source.proposed.generation,
            source.proposed.previous_assignment_sha256,
            source.proposed.enabled_for_new_exposure,
            source.proposed.live_authorized,
        ),
        (
            heads.ledger_sha256,
            heads.order_sha256,
            heads.capacity_sha256,
            heads.effect_watermark,
            heads.attempt_sha256,
            heads.control_revision,
            heads.lease_generation,
        ),
        (
            value.reference.schema_id,
            value.reference.object_ref.object_sha256,
            value.reference.object_ref.byte_count,
            value.reference.object_ref.codec_version,
            value.reference.semantic_sha256,
        ),
        (value.canonical.receipt.semantic_sha256, value.canonical.receipt.commit.sequence),
        (
            source.fence.lease_sha256,
            source.checked_at,
            source.valid_until,
            command.requested_at,
            command.expires_at,
            auth.authenticated_at,
            auth.session_expires_at,
            value.prefix.recorded_at,
        ),
        (
            value.prefix.before_assignment is None,
            value.prefix.after_assignment.semantic_sha256,
            value.reconciliation is None,
        ),
    )


def _bounded_native(value):
    if value is None or type(value) is bool:
        return True
    if type(value) is str:
        return 0 < len(value) <= 2048
    if type(value) is int:
        return 0 <= value < 2**63
    if type(value) is datetime:
        return value.tzinfo is UTC
    if type(value) is tuple:
        return len(value) <= 16 and all(_bounded_native(item) for item in value)
    return False


def _detached(case, *, selected):
    """Second-lifetime inputs contain paths/native copies, never the old graph."""
    assert not case.thread.is_alive()
    assert case.close_calls == case.guard_exits == len(case.acquires) == len(case.releases) == 1
    assert case.disposals == ["dispose-venue", "dispose-account"]
    assert case.release_attempts == [case.acquires[0].fence]
    assert case.releases[0].lease_sha256 == case.acquires[0].semantic_sha256
    descriptor, command = case.descriptor, case.issued.command
    row = None
    if selected:
        rows = original_g._mapped(
            original_g._table(case.operation_end, daily_runtime_assignments),
            daily_runtime_assignments,
        )
        assert len(rows) == 1
        row = rows[0]
    else:
        assert original_g._table(case.operation_end, daily_runtime_assignments) == ()
        assert original_g._table(case.operation_end, daily_runtime_assignment_heads) == ()
    expected = (
        None
        if row is None
        else (
            (descriptor.account_id, descriptor.account_binding_sha256, descriptor.stream_id),
            _receipt(case.issued.receipt),
            (descriptor.after_assignment_sha256, 1, None, False, False),
            (
                descriptor.ledger_sha256,
                descriptor.order_sha256,
                descriptor.capacity_sha256,
                descriptor.effect_watermark,
                descriptor.attempt_sha256,
                descriptor.control_revision,
                descriptor.lease_generation,
            ),
            (
                descriptor.dependency_schema_id,
                descriptor.dependency_object_sha256,
                descriptor.dependency_byte_count,
                descriptor.dependency_codec_version,
                descriptor.dependency_semantic_sha256,
            ),
            (case.study.genesis.restored.receipt.semantic_sha256, 1),
            (
                descriptor.original_lease_sha256,
                descriptor.checked_at,
                descriptor.valid_until,
                command.requested_at,
                command.expires_at,
                case.issued.prepared.record.authentication.authenticated_at,
                case.issued.prepared.record.authentication.session_expires_at,
                row["recorded_at"].replace(tzinfo=UTC),
            ),
            (True, descriptor.after_assignment_sha256, True),
        )
    )
    assert expected is None or _bounded_native(expected)
    proposed = case.dependency_record.proposed
    return SimpleNamespace(
        study=SimpleNamespace(
            paths={name: Path(str(path)) for name, path in case.study.paths.items()}
        ),
        configuration_path=Path(str(case.configuration_path)),
        configuration_bytes=bytes(case.configuration_bytes),
        lock_path=Path(str(case.lock_path)),
        lock_identity=tuple(case.lock_identity),
        account_id=descriptor.account_id,
        stream_id=descriptor.stream_id,
        policy_sha256=case.configuration.lease_policy().semantic_sha256,
        historical_r1_sha256=descriptor.original_lease_sha256,
        historical_generation=descriptor.lease_generation,
        expected=expected,
        selected=selected,
        metadata=(
            proposed.strategy.name,
            proposed.strategy.version,
            proposed.configuration_sha256,
            proposed.instrument_symbols,
            proposed.policy.policy_id,
            proposed.effective_at,
        ),
    )


@contextmanager
def _observe_reuse():
    """Observe original successful returns; never patch pinned effect methods."""
    probe = SimpleNamespace(
        owner=None,
        account=None,
        venue=None,
        coordinator=None,
        guard=None,
        read_engine=None,
        lease=None,
        releases=[],
        release_calls=[],
        close_returns=[],
        associations=[],
        schema=[],
        verification_returns=[],
        metadata_reads=0,
        trace=[],
        faults=[],
        connects=[],
        caller=threading.current_thread(),
        guard_identity=None,
        forbidden=[],
    )
    labels = {
        ContinuousReadinessOwner.__init__.__code__: "owner",
        ContinuousSimulationFactory.__init__.__code__: "factory",
        ContinuousSimulationFactory.close.__code__: "close",
        ContinuousSimulationFactory.execute.__code__: "execute",
        _ReadinessRuntime.verify.__code__: "verify",
        SqlAccountCoordinator.acquire.__code__: "acquire",
        SqlAccountCoordinator.release.__code__: "release",
        LocalInstanceGuard.__enter__.__code__: "guard-enter",
        LocalInstanceGuard.__exit__.__code__: "guard-exit",
        Engine.connect.__code__: "connect",
        Engine.dispose.__code__: "dispose",
        SqlRuntimeOwnerAssociations.require_association.__code__: "association",
        verify_operational_schema.__code__: "schema",
        SqlContinuousSelectionReadModel.read.__code__: "metadata",
        ReadinessReadStore.close.__code__: "read-close",
        ContinuousReadinessOwner.stop.__code__: "owner-stop",
        SqlRuntimeAssignmentPublication.publish.__code__: "publish",
        SqlRuntimeOwnerCommands.prepare.__code__: "prepare-request",
        SqlRuntimeOwnerCommands.append_in_transaction.__code__: "append-request",
        LocalRuntimeOwnerAuthenticator.authenticate.__code__: "authenticate-command",
        LocalResearchArtifactStore.put.__code__: "put-object",
    }
    monitor, tool = sys.monitoring, 3
    previous_profile = sys.getprofile()
    owned = False
    enabled, registered = [], []

    def observe(frame, event, returned):
        try:
            label, actual = labels[frame.f_code], frame.f_locals.get("self")
            thread = threading.current_thread()
            if event == "call":
                if label in (
                    "execute",
                    "publish",
                    "prepare-request",
                    "append-request",
                    "authenticate-command",
                    "put-object",
                ):
                    probe.forbidden.append(label)
                elif label == "close":
                    probe.trace.append(("close-call", thread))
                elif label == "release":
                    probe.release_calls.append((actual, frame.f_locals["fence"], thread))
                return
            if label == "owner":
                probe.owner = actual
            elif label == "factory":
                probe.account, probe.venue = actual.engine, actual.venue_engine
                probe.coordinator = actual.coordinator
                probe.trace.append(("factory-return", thread))
            elif label == "acquire":
                if probe.lease is not None:
                    probe.faults.append(AssertionError("more than one inspection acquisition"))
                probe.lease = returned
                probe.trace.append(("acquire-return", thread))
            elif label == "release":
                probe.releases.append((actual, returned, thread))
                probe.trace.append(("release-return", thread))
            elif label == "close":
                probe.close_returns.append(returned)
                probe.trace.append(("close-return", thread))
            elif label == "guard-enter":
                probe.guard = actual
                info = os.fstat(actual.fileno())
                probe.guard_identity = info.st_dev, info.st_ino
            elif label == "guard-exit" and actual is probe.guard:
                probe.trace.append(("guard-exit-return", thread))
            elif label == "connect" and actual in (probe.account, probe.venue, probe.read_engine):
                probe.connects.append(returned)
            elif label == "dispose":
                for engine, name in (
                    (probe.account, "account-dispose-return"),
                    (probe.venue, "venue-dispose-return"),
                    (probe.read_engine, "read-dispose-return"),
                ):
                    if actual is engine and engine is not None:
                        probe.trace.append((name, thread))
            elif label == "association":
                values = _association_values(frame.f_locals["value"])
                if len(probe.associations) >= 64 or not _bounded_native(values):
                    probe.faults.append(AssertionError("unbounded installed-history observation"))
                else:
                    probe.associations.append((values, thread))
            elif label == "schema" and frame.f_locals["continuous_integrity"] is not None:
                reader = frame.f_locals["continuous_integrity"]
                probe.schema.append(
                    (
                        frame.f_locals["engine"],
                        reader.engine,
                        frame.f_locals["require_phase_zero_facts"],
                        frame.f_locals["research_codec"] is personal_codec,
                        thread,
                    )
                )
            elif label == "verify":
                probe.verification_returns.append((returned, thread))
            elif label == "metadata" and actual.engine is probe.read_engine:
                probe.metadata_reads += 1
            elif label == "read-close":
                probe.trace.append(("read-close-return", thread))
            elif label == "owner-stop" and actual is probe.owner:
                probe.trace.append(("owner-stop-return", thread))
        except BaseException as error:
            # Original proofs may catch callback exceptions. Retain actual faults
            # for outer failure after natural cleanup; never turn them into a pass.
            probe.faults.append(error)
        finally:
            del frame

    def on_start(code, offset):
        frame = sys._getframe(1)
        try:
            observe(frame, "call", None)
        finally:
            del frame

    def on_return(code, offset, returned):
        frame = sys._getframe(1)
        try:
            observe(frame, "return", returned)
        finally:
            del frame

    primary = None
    try:
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-installed-history-reuse")
        owned = True
        for event, callback in (
            (monitor.events.PY_START, on_start),
            (monitor.events.PY_RETURN, on_return),
        ):
            registered.append(event)
            assert monitor.register_callback(tool, event, callback) is None
        for code in labels:
            assert monitor.get_local_events(tool, code) == 0
            enabled.append(code)
            monitor.set_local_events(tool, code, monitor.events.PY_START | monitor.events.PY_RETURN)
        yield probe
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        if owned:
            for code in enabled:
                try:
                    monitor.set_local_events(tool, code, 0)
                    assert monitor.get_local_events(tool, code) == 0
                except BaseException as error:
                    errors.append(error)
            for event in registered:
                try:
                    monitor.register_callback(tool, event, None)
                except BaseException as error:
                    errors.append(error)
            try:
                assert monitor.get_events(tool) == 0
                assert monitor.get_tool(tool) == "aqt-installed-history-reuse"
                monitor.free_tool_id(tool)
                assert monitor.get_tool(tool) is None
            except BaseException as error:
                errors.append(error)
        errors.extend(probe.faults)
        if sys.getprofile() is not previous_profile:
            errors.append(AssertionError("original profiling state changed"))
        if errors:
            if primary is not None:
                errors.insert(0, primary)
            raise BaseExceptionGroup("installed-history observation and cleanup failed", errors)


def _lease_delta(data, before, after, probe):
    assert after.financial == before.financial
    assert len(after.leases) == len(before.leases) + 1
    assert all(row in after.leases for row in before.leases)
    lease_rows = [row for row in after.leases if row not in before.leases]
    assert len(lease_rows) == 1
    lease = account_lease_from_row(lease_rows[0])
    assert type(probe.lease) is AccountLease and lease == probe.lease
    assert lease.account_id == data.account_id
    assert lease.fencing_generation == before.heads[0]["last_fencing_generation"] + 1
    assert lease.fencing_generation > data.historical_generation
    assert lease.revision_number == 1 and lease.previous_lease_sha256 is None
    assert lease.policy_sha256 == data.policy_sha256
    assert lease.expires_at - lease.acquired_at == timedelta(seconds=60)
    assert lease.semantic_sha256 != data.historical_r1_sha256
    assert len(after.releases) == len(before.releases) + 1
    assert all(row in after.releases for row in before.releases)
    release_rows = [row for row in after.releases if row not in before.releases]
    assert len(release_rows) == 1
    release = account_lease_release_from_row(release_rows[0])
    assert type(release) is AccountLeaseRelease
    assert probe.releases == [(probe.coordinator, release, probe.owner._thread)]
    assert probe.release_calls == [(probe.coordinator, lease.fence, probe.owner._thread)]
    assert probe.close_returns == [release]
    assert release.fence == lease.fence and release.lease_sha256 == lease.semantic_sha256
    assert release.policy_sha256 == lease.policy_sha256
    assert lease.acquired_at <= release.released_at < lease.expires_at
    assert before.heads == (
        dict(
            account_id=data.account_id,
            last_fencing_generation=before.heads[0]["last_fencing_generation"],
            current_fencing_generation=None,
            current_lease_sha256=None,
            updated_at=before.heads[0]["updated_at"],
        ),
    )
    assert after.heads == (
        dict(
            account_id=data.account_id,
            last_fencing_generation=lease.fencing_generation,
            current_fencing_generation=None,
            current_lease_sha256=None,
            updated_at=release_rows[0]["released_at"],
        ),
    )


def _read_again(data):
    before = _snapshot(data.study)
    assert data.configuration_path.read_bytes() == data.configuration_bytes
    with _observe_reuse() as probe:
        manager = configured_readiness_reads(
            configuration_path=str(data.configuration_path),
            account_id=data.account_id,
            instance_lock=str(data.lock_path),
        )
        assert probe.owner is not None and probe.owner._thread is None
        assert probe.owner._limits == ReadinessOwnerLimits()
        with manager as port:
            assert type(port) is ReadinessReadStore and port._owner is probe.owner
            probe.read_engine = port._engine
            assert probe.read_engine is not probe.account and probe.read_engine is not probe.venue
            assert type(probe.read_engine.pool) is NullPool
            assert dict(probe.read_engine.url.query) == {"mode": "ro", "uri": "true"}
            assert probe.read_engine.url.database == data.study.paths["database_path"].as_uri()
            assert probe.owner._thread.is_alive()
            admitted = _snapshot(data.study)
            assert admitted.financial == before.financial and admitted.releases == before.releases
            assert len(admitted.leases) == len(before.leases) + 1
            assert admitted.heads[0]["current_lease_sha256"] == probe.lease.semantic_sha256
            assert admitted.heads[0]["current_fencing_generation"] == probe.lease.fencing_generation
            value = port.read()
            assert type(value) is ContinuousSelectionSnapshot
            assert (
                value.account_id == data.account_id and value.verification == "row_integrity_only"
            )
            assert value.checkpoint.stream_id == data.stream_id and value.checkpoint.sequence == 1
            assert value.state == ("selected" if data.selected else "unselected")
            if data.selected:
                selection = value.selection
                assert selection.generation == 1
                assert selection.enabled_for_new_exposure is selection.live_authorized is False
                assert (
                    selection.strategy_name,
                    selection.strategy_version,
                    selection.configuration_sha256,
                    selection.instrument_symbols,
                    selection.policy_id,
                    selection.effective_at,
                ) == data.metadata
                assert selection.recorded_at == data.expected[6][-1]
            else:
                assert value.selection is None
        assert port.status() == ReadinessReadStoreStatus("closed", False, True, None)
        owner = probe.owner
        status = owner.status()
        assert status.phase == "stopped" and not status.busy and status.cleanup_complete
        assert status.primary_failure is status.cleanup_failure is None
        assert owner._thread is not None and not owner._thread.is_alive()
    after = _snapshot(data.study)
    _lease_delta(data, before, after, probe)
    assert data.configuration_path.read_bytes() == data.configuration_bytes
    assert probe.guard._descriptor is None and probe.guard_identity == data.lock_identity
    assert probe.forbidden == [] and probe.metadata_reads == 1
    assert probe.schema == [(probe.account, probe.account, True, True, owner._thread)]
    assert len(probe.verification_returns) == 1
    assert type(probe.verification_returns[0][0]) is int
    assert probe.verification_returns[0][1] is owner._thread
    assert all(connection.closed for connection in probe.connects)
    assert probe.connects
    if data.selected:
        assert probe.associations
        assert all(
            values == data.expected and thread is owner._thread
            for values, thread in probe.associations
        )
    else:
        assert probe.associations == []
    labels = [name for name, thread in probe.trace]
    for name in (
        "acquire-return",
        "factory-return",
        "close-call",
        "release-return",
        "venue-dispose-return",
        "account-dispose-return",
        "close-return",
        "guard-exit-return",
    ):
        assert labels.count(name) == 1
        assert next(thread for label, thread in probe.trace if label == name) is owner._thread
    for name in ("read-dispose-return", "read-close-return", "owner-stop-return"):
        assert labels.count(name) == 1
        assert next(thread for label, thread in probe.trace if label == name) is probe.caller
    assert labels.index("read-dispose-return") < labels.index("read-close-return")
    assert labels.index("read-close-return") < labels.index("close-call")
    assert labels.index("close-call") < labels.index("release-return")
    assert labels.index("release-return") < labels.index("venue-dispose-return")
    assert labels.index("venue-dispose-return") < labels.index("account-dispose-return")
    assert labels.index("account-dispose-return") < labels.index("close-return")
    assert labels.index("close-return") < labels.index("guard-exit-return")
    assert labels.index("guard-exit-return") < labels.index("owner-stop-return")
    with LocalInstanceGuard(data.lock_path) as guard:
        info = os.fstat(guard.fileno())
        assert (info.st_dev, info.st_ino) == data.lock_identity


def test_ambiguous_committed_h_install_is_authenticated_by_separate_original_read_owners(
    tmp_path, monkeypatch
):
    with (
        monkeypatch.context() as first_lifetime,
        original_h._case(tmp_path, first_lifetime, mode="commit-failure") as case,
    ):
        original_h._prepare(case)
        original_h._call(case)
        original_h._unavailable(
            case, original_h._join_caller(case), "terminal-install", "installation_failed"
        )
        status = original_h._closed(case)
        assert status.primary_failure == "installation_failed"
        assert case.owner._primary_error is case.primary
        assert case.guard_primaries == [case.primary]
        assert case.pub_calls == case.pub_return_events == case.sql_inserts == 1
        original_h._facts(case, returned=False, digest=None)
        original_g._disabled_b(case, case.requested, case.operation_end)
        original_h._no_replay(case)
    primary, traceback = case.primary, case.primary.__traceback__
    assert traceback is not None
    # H retains operation failure separately from successful context cleanup.
    assert case.context_error is case.owner._context_error is None
    assert case.operation_error is case.owner._primary_error is primary
    data = _detached(case, selected=True)
    _read_again(data)
    assert case.primary is primary and primary.__traceback__ is traceback
    assert case.operation_error is case.owner._primary_error is primary
    assert case.context_error is case.owner._context_error is None
    assert case.guard_primaries == [primary]
    assert not case.thread.is_alive() and case.close_calls == len(case.releases) == 1


def test_physically_rolled_back_g_install_remains_unselected_under_separate_read_owners(
    tmp_path, monkeypatch
):
    with (
        monkeypatch.context() as first_lifetime,
        original_g._installation_case(tmp_path, first_lifetime, mode="rollback") as case,
    ):
        original_g._start_and_issue(case)
        original_g._join(case)
        assert case.operation_error is case.context_error is case.primary
        assert case.sql_inserts == case.pub_calls == 1 and case.pub_return_events == 0
        assert case.operation_end.financial == case.requested.financial
        assert case.observed.publication_started and not case.observed.publication_returned
        assert case.observed.assignment_sha256 is None and case.result is None
    primary, traceback = case.primary, case.primary.__traceback__
    assert traceback is not None
    data = _detached(case, selected=False)
    _read_again(data)
    assert case.primary is primary and primary.__traceback__ is traceback
    assert case.operation_error is case.context_error is primary
    assert not case.thread.is_alive() and case.close_calls == len(case.releases) == 1
