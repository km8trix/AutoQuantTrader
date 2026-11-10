"""Fresh migrated synthetic state into the unchanged direct offline factory.

These are new disposable fixtures, not retained-history or OS-process tests.
Authentication is modeled only in the existing test-local request helper.
"""

import json
import os
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from apps.trader.continuous_simulation_factory import (
    ContinuousSimulationFactoryError,
    load_continuous_configuration,
    run_continuous_operation,
)
from apps.trader.synthetic_initial_selection import prepare_synthetic_initial_selection
from apps.trader.synthetic_offline_configuration import export_synthetic_offline_configuration
from apps.trader.synthetic_session_capture import capture_synthetic_bootstrap
from apps.trader.synthetic_session_genesis import (
    initialize_synthetic_session,
    reconstruct_selected_synthetic_session_owners,
    reconstruct_synthetic_session_owners,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.application.continuous_process import (
    ContinuousProcessLimits,
    ContinuousProcessRequest,
)
from packages.application.synthetic_continuous_inputs import synthetic_continuous_inputs
from packages.domain.account_coordinator import AccountCoordinatorError
from packages.domain.clock import SimulatedClock
from packages.domain.forward_capture_contracts import CAPTURE_SCHEMA, ForwardCaptureRecord
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
)
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.persistence.account_coordinator import account_lease_from_row
from packages.persistence.continuous_account_schema import CONTINUOUS_ACCOUNT_TABLES
from packages.persistence.daily_runtime_risk import DailyRuntimeRiskConflict
from packages.persistence.daily_runtime_risk_schema import (
    DAILY_RUNTIME_TABLES,
    daily_runtime_assignment_heads,
)
from packages.persistence.database import EXPECTED_SCHEMA_REVISION, create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)
from tests.integration.test_continuous_synthetic_initial_selection import _publish, _request
from tests.integration.test_continuous_synthetic_session_genesis import PINS

ROOT = Path(__file__).resolve().parents[2]
FINANCIAL_TABLES = (
    *CONTINUOUS_ACCOUNT_TABLES,
    *DAILY_RUNTIME_TABLES,
    *JOURNAL_TABLES,
    phase5_operational_control_transitions,
    phase5_operational_control_heads,
    phase5_operational_control_completions,
)


def _exclusive_file(path, payload=b""):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)


@contextmanager
def _study(parent, *, install=True):
    root = parent.resolve() / "fresh-synthetic-offline"
    root.mkdir(mode=0o700)
    database, venue_database = root / "account.sqlite", root / "venue.sqlite"
    _exclusive_file(database)
    _exclusive_file(venue_database)
    # The original migration environment honors this attribute before consulting
    # an ambient URL. Config() also avoids changing logging via alembic.ini.
    url = f"sqlite+pysqlite:///{database}"
    migration = Config()
    migration.set_main_option("script_location", str(ROOT / "migrations"))
    migration.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    migration.attributes["aqt_explicit_database_url"] = url
    command.upgrade(migration, EXPECTED_SCHEMA_REVISION)
    with ExitStack() as cleanup:
        account = create_database_engine(url)
        cleanup.callback(account.dispose)
        venue = create_database_engine(f"sqlite+pysqlite:///{venue_database}")
        cleanup.callback(venue.dispose)
        metadata.create_all(venue, tables=JOURNAL_TABLES)
        with account.connect() as connection:
            assert tuple(
                connection.scalars(sa.text("SELECT version_num FROM alembic_version"))
            ) == (EXPECTED_SCHEMA_REVISION,)
        artifacts = LocalResearchArtifactStore(root / "account-objects")
        venue_artifacts = LocalResearchArtifactStore(root / "venue-objects")
        synthetic = synthetic_continuous_inputs(
            fixture="regime", pins=PINS, session_count=4, warmup_count=1
        )
        producer = VersionPin(
            "synthetic-capture", "offline-test-model-1", content_digest("capture")
        )
        journal = SqlDurableJournal(
            account, codec=codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
        )
        bootstrap = capture_synthetic_bootstrap(
            synthetic,
            calendar_pin=VersionPin(
                "synthetic-calendar",
                "offline-test-model-1",
                content_digest(synthetic.inputs.spec.calendar),
            ),
            producer_pin=producer,
            journal=journal,
            publisher=SqlForwardCapturePublication(account, journal=journal),
            artifacts=artifacts,
            codec=codec,
        )
        ports = dict(
            account_engine=account,
            venue_engine=venue,
            account_artifacts=artifacts,
            venue_artifacts=venue_artifacts,
            clock=SimulatedClock(bootstrap.inputs.spec.initialized_at),
            monotonic_now_ns=lambda: 1_000_000_000,
            epoch_id="synthetic-offline-test-model-1",
            owner_id="synthetic-offline-startup",
            venue_pin=VersionPin(
                "synthetic-venue", "offline-test-model-1", content_digest("venue")
            ),
            quote_producer=producer,
        )
        genesis = initialize_synthetic_session(bootstrap, **ports)
        study = SimpleNamespace(
            root=root,
            genesis=genesis,
            ports=ports,
            lease=genesis.account.coordinator.acquire("synthetic-offline-export"),
            paths=dict(
                database_path=database,
                artifact_root=artifacts._root,
                venue_database_path=venue_database,
                venue_artifact_root=venue_artifacts._root,
            ),
        )
        primary = None
        try:
            study.owners = reconstruct_synthetic_session_owners(genesis, lease=study.lease)
            if install:
                study.dependencies = prepare_synthetic_initial_selection(
                    genesis, owners=study.owners, lease=study.lease
                )
                study.request = _request(study)
                study.assignment = _publish(study, study.request)
                study.owners = reconstruct_selected_synthetic_session_owners(
                    genesis, lease=study.lease
                )
            yield study
        except BaseException as error:
            primary = error
            raise
        finally:
            # Both engine callbacks still run if this caller-owned release fails.
            # Pytest reports test-body and fixture teardown failures separately.
            try:
                _release_setup(study)
            except BaseException as error:
                if primary is not None:
                    raise BaseExceptionGroup(
                        "synthetic fixture and cleanup failed", [primary, error]
                    ) from None
                raise


@pytest.fixture
def selected(tmp_path):
    with _study(tmp_path) as study:
        yield study


def _release_setup(study):
    if study.lease is not None:
        coordinator = study.genesis.account.coordinator
        release = coordinator.release(study.lease.fence)
        assert release.lease_sha256 == study.lease.semantic_sha256
        study.lease = None
        assert coordinator.current() is None


def _export(study, **changes):
    arguments = dict(
        owners=study.owners,
        lease=study.lease,
        owner_id="synthetic-offline-reader",
        **study.paths,
    )
    arguments.update(changes)
    return export_synthetic_offline_configuration(study.genesis, **arguments)


def _rows(engine, tables):
    with engine.connect() as connection:
        return tuple(
            tuple(
                tuple(row)
                for row in connection.execute(sa.select(table).order_by(*table.primary_key.columns))
            )
            for table in tables
        )


def _objects(study):
    return tuple(
        tuple(sorted((path.name, path.read_bytes()) for path in study.paths[key].iterdir()))
        for key in ("artifact_root", "venue_artifact_root")
    )


def _facts(study):
    return (
        _rows(study.ports["account_engine"], FINANCIAL_TABLES),
        _rows(study.ports["venue_engine"], JOURNAL_TABLES),
        _objects(study),
        _rows(
            study.ports["account_engine"], (phase2_account_leases, phase2_account_lease_releases)
        ),
    )


def _map_path(study):
    payload = codec.encode_record(study.owners.runtime.producer_map)
    return study.paths["artifact_root"] / (sha256(payload).hexdigest() + ".json")


def _request_file(study, configuration):
    path = study.root / "restore.json"
    _exclusive_file(path, codec.encode_record(configuration))
    assert load_continuous_configuration(path) == configuration
    return ContinuousProcessRequest(
        account_id=study.genesis.scope.account_id,
        operation_id="first-fresh-synthetic-restore",
        configuration_path=path,
        objects=tuple(reference.object_ref for reference in configuration.references),
    )


def _cold_call(study, request):
    _release_setup(study)
    financial = _facts(study)[:3]
    study.ports["account_engine"].dispose()
    study.ports["venue_engine"].dispose()
    primary = None
    try:
        return run_continuous_operation(request, stop_requested=lambda: False)
    except BaseException as error:
        primary = error
        raise
    finally:
        # Use fresh SQL connections, not the modeled coordinator whose clock is
        # now earlier than the factory's genuine actual-time recovery watermark.
        try:
            with ExitStack() as cleanup:
                account = create_database_engine(
                    f"sqlite+pysqlite:///{study.paths['database_path']}"
                )
                cleanup.callback(account.dispose)
                venue = create_database_engine(
                    f"sqlite+pysqlite:///{study.paths['venue_database_path']}"
                )
                cleanup.callback(venue.dispose)
                with account.connect() as connection:
                    head = (
                        connection.execute(sa.select(phase2_account_lease_heads)).mappings().one()
                    )
                    assert head["current_lease_sha256"] is None
                    assert head["current_fencing_generation"] is None
                assert (
                    _rows(account, FINANCIAL_TABLES),
                    _rows(venue, JOURNAL_TABLES),
                    _objects(study),
                ) == financial
        except BaseException as error:
            if primary is not None:
                raise BaseExceptionGroup(
                    "fresh offline load and cleanup failed", [primary, error]
                ) from None
            raise


def test_export_retains_only_original_map_and_reuses_original_references(selected):
    study = selected
    before = _facts(study)
    assert not _map_path(study).exists()
    result = _export(study)
    assert result.inputs is study.genesis.restored.receipt.commit.request
    assert result.venue_model.object_ref is study.owners.runtime.venue_reference.object_ref
    assert result.venue_model.semantic_sha256 == study.owners.runtime.venue_model.semantic_sha256
    assert result.producer_map.semantic_sha256 == study.owners.runtime.producer_map.semantic_sha256
    assert _map_path(study).read_bytes() == codec.encode_record(study.owners.runtime.producer_map)
    assert result.operation == "restore"
    assert result.capture_evidence_class == "synthetic_fixture"
    assert result.clock_profile == "explicit_simulation_time_model"
    assert result.benchmark_instrument_id == study.owners.runtime.benchmark_instrument_id
    assert result.lease_policy() == study.genesis.account.coordinator._authority.policy
    assert (
        result.lease_ttl_microseconds,
        result.maximum_in_flight_microseconds,
        result.takeover_safety_microseconds,
    ) == (60_000_000, 5_000_000, 10_000_000)
    after = _facts(study)
    assert before[:2] == after[:2] and before[3] == after[3]
    assert after[2][1] == before[2][1]
    assert set(after[2][0]) - set(before[2][0]) == {
        (_map_path(study).name, _map_path(study).read_bytes())
    }
    assert set(before[2][0]).issubset(after[2][0])
    assert _export(study) == result
    assert _facts(study) == after
    assert study.genesis.account.coordinator.current() == study.lease
    assert study.owners.owners.commands.authenticator.security._enabled is False


def test_first_direct_factory_load_reconstructs_fresh_selected_state_and_releases(selected):
    study = selected
    configuration = _export(study)
    request = _request_file(study, configuration)
    assert request.limits == ContinuousProcessLimits()
    before = _rows(study.ports["account_engine"], (phase2_account_leases,))
    payload = _cold_call(study, request)
    assert len(payload) <= 16 * 1024
    assert json.loads(payload) == {
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
    assert str(study.root).encode() not in payload
    with study.ports["account_engine"].connect() as connection:
        leases = connection.execute(sa.select(phase2_account_leases)).mappings().all()
        assert len(leases) == len(before[0]) + 1
        recovered = account_lease_from_row(max(leases, key=lambda row: row["fencing_generation"]))
        releases = connection.execute(sa.select(phase2_account_lease_releases)).mappings().all()
        assert any(row["lease_sha256"] == recovered.semantic_sha256 for row in releases)
    assert recovered.owner_id.startswith("offline-owner-")
    assert recovered.policy_sha256 == configuration.lease_policy().semantic_sha256
    assert recovered.acquired_at > study.request.command.expires_at


@pytest.mark.parametrize(
    "field", ["database_path", "artifact_root", "venue_database_path", "venue_artifact_root"]
)
def test_each_nonprivate_storage_path_rejects_before_map_retention(selected, field):
    path = selected.paths[field]
    old = path.stat().st_mode & 0o777
    before = _facts(selected)
    path.chmod(old | 0o040)
    try:
        with pytest.raises(
            ContinuousSimulationFactoryError, match="OFFLINE_EXISTING_PRIVATE_STORAGE_REQUIRED"
        ):
            _export(selected)
    finally:
        path.chmod(old)
    assert _facts(selected) == before
    assert not _map_path(selected).exists()


@pytest.mark.parametrize("kind", ["relative", "env", "symlink", "hardlink", "missing", "other"])
def test_nonoriginal_database_path_rejects_before_any_retention(selected, kind):
    study = selected
    before = _facts(study)
    path = study.root / "other.sqlite"
    expected = ValueError
    if kind == "relative":
        path = Path("account.sqlite")
    elif kind == "env":
        path = study.root / ".env-unread.sqlite"
    elif kind == "symlink":
        path.symlink_to(study.paths["database_path"])
    elif kind == "hardlink":
        os.link(study.paths["database_path"], path)
    elif kind == "missing":
        expected = FileNotFoundError
    else:
        _exclusive_file(path)
    try:
        with pytest.raises(expected):
            _export(study, database_path=path)
    finally:
        if kind == "hardlink":
            path.unlink()
    assert _facts(study) == before
    assert not _map_path(study).exists()


@pytest.mark.parametrize(
    "field,other",
    [("database_path", "venue_database_path"), ("artifact_root", "venue_artifact_root")],
)
def test_aliased_storage_rejects_before_map_retention(selected, field, other):
    before = _facts(selected)
    with pytest.raises(ValueError, match="INDEPENDENT_SYNTHETIC_STORAGE_REQUIRED"):
        _export(selected, **{field: selected.paths[other]})
    assert _facts(selected) == before
    assert not _map_path(selected).exists()


def test_empty_b_cannot_be_exported_as_selected(tmp_path):
    with _study(tmp_path, install=False) as study:
        before = _facts(study)
        with pytest.raises(
            ValueError, match="OFFLINE_SYNTHETIC_DISABLED_INITIAL_SELECTION_REQUIRED"
        ):
            _export(study)
        assert _facts(study) == before
        assert not _map_path(study).exists()


def test_released_setup_lease_cannot_export(selected):
    lease = selected.lease
    _release_setup(selected)
    before = _facts(selected)
    with pytest.raises(AccountCoordinatorError):
        _export(selected, lease=lease)
    assert _facts(selected) == before
    assert not _map_path(selected).exists()


def test_rebound_current_owner_graph_cannot_export(selected):
    before = _facts(selected)
    with pytest.raises(ValueError, match="ORIGINAL_SYNTHETIC_SELECTION_BINDINGS_REQUIRED"):
        _export(selected, owners=replace(selected.owners, account=selected.genesis.account))
    assert _facts(selected) == before
    assert not _map_path(selected).exists()


def _later_halt(study):
    return SqlOperationalControlRepository(
        engine=study.ports["account_engine"], clock=study.ports["clock"]
    ).apply(
        OperationalControlCommand(
            study.genesis.scope.account_id,
            "later-synthetic-offline-halt",
            OperationalControlCommandKind.HALT,
            OperationalControlState.HALTED,
            OperationalControlActor(
                "synthetic-test-system",
                OperationalControlActorKind.SYSTEM,
                content_digest("later-halt"),
                None,
            ),
            "TEST_LATER_HALTED_HEAD",
            content_digest("later-halt"),
            study.ports["clock"].now(),
        )
    )


def test_changed_halted_head_rejects_before_map_retention(selected):
    _later_halt(selected)
    before = _facts(selected)
    with pytest.raises(ValueError, match="OFFLINE_SYNTHETIC_DISABLED_INITIAL_SELECTION_REQUIRED"):
        _export(selected)
    assert _facts(selected) == before
    assert not _map_path(selected).exists()


def test_map_write_failure_preserves_original_error_and_current_state(selected, monkeypatch):
    sentinel = RuntimeError("test-only-map-write-failed")
    before = _facts(selected)
    calls = []

    def fail(store, payload, **kwargs):
        assert store is selected.owners.runtime.artifacts
        assert payload == codec.encode_record(selected.owners.runtime.producer_map)
        calls.append(payload)
        raise sentinel

    with monkeypatch.context() as patch:
        patch.setattr(LocalResearchArtifactStore, "put", fail)
        with pytest.raises(RuntimeError) as caught:
            _export(selected)
    assert caught.value is sentinel and len(calls) == 1
    assert _facts(selected) == before
    assert not _map_path(selected).exists()


def test_final_sql_check_rejects_changed_control_and_preserves_retained_map(selected, monkeypatch):
    original = LocalResearchArtifactStore.put
    changed = []

    def retain_then_change(store, payload, **kwargs):
        result = original(store, payload, **kwargs)
        changed.append(_later_halt(selected))
        return result

    with monkeypatch.context() as patch:
        patch.setattr(LocalResearchArtifactStore, "put", retain_then_change)
        with pytest.raises(
            DailyRuntimeRiskConflict,
            match=r"^captured (row inventory|immutable row bytes) changed$",
        ):
            _export(selected)
    assert len(changed) == 1
    assert _map_path(selected).read_bytes() == codec.encode_record(
        selected.owners.runtime.producer_map
    )
    assert (
        SqlOperationalControlRepository(
            engine=selected.ports["account_engine"], clock=selected.ports["clock"]
        ).load(selected.genesis.scope.account_id)
        == changed[0]
    )
    assert selected.genesis.account.coordinator.current() == selected.lease


def test_original_request_reference_guard_rejects_before_factory_acquisition(selected):
    configuration = _export(selected)
    request = _request_file(selected, configuration)
    request = replace(request, objects=tuple(reversed(request.objects)))
    before = _rows(selected.ports["account_engine"], (phase2_account_leases,))
    with pytest.raises(ContinuousSimulationFactoryError, match="OFFLINE_OPERATION_FAILED"):
        _cold_call(selected, request)
    assert _rows(selected.ports["account_engine"], (phase2_account_leases,)) == before


@pytest.mark.parametrize("field", ["inputs", "venue_model", "producer_map"])
def test_original_factory_rejects_changed_reference_before_acquiring(selected, field):
    configuration = _export(selected)
    changed = replace(getattr(configuration, field), semantic_sha256="0" * 64)
    request = _request_file(selected, replace(configuration, **{field: changed}))
    before = _rows(selected.ports["account_engine"], (phase2_account_leases,))
    with pytest.raises(ContinuousSimulationFactoryError, match="OFFLINE_OPERATION_FAILED"):
        _cold_call(selected, request)
    assert _rows(selected.ports["account_engine"], (phase2_account_leases,)) == before


def test_original_factory_failure_after_acquisition_releases_and_preserves_adverse_state(selected):
    study = selected
    configuration = _export(study)
    request = _request_file(study, configuration)
    with study.ports["account_engine"].connect() as connection:
        before = set(connection.scalars(sa.select(phase2_account_leases.c.lease_sha256)))
    with study.ports["account_engine"].begin() as connection:
        changed = connection.execute(
            sa.delete(daily_runtime_assignment_heads).where(
                daily_runtime_assignment_heads.c.account_id == study.genesis.scope.account_id
            )
        )
        assert changed.rowcount == 1
    # _cold_call snapshots this deliberately damaged state after setup release;
    # its finally requires unchanged financial/venue/objects and a null head.
    with pytest.raises(ContinuousSimulationFactoryError, match=r"^OFFLINE_OPERATION_FAILED$"):
        _cold_call(study, request)
    with study.ports["account_engine"].connect() as connection:
        added = [
            row
            for row in connection.execute(sa.select(phase2_account_leases)).mappings()
            if row["lease_sha256"] not in before
        ]
        assert len(added) == 1
        recovered = account_lease_from_row(added[0])
        releases = (
            connection.execute(
                sa.select(phase2_account_lease_releases).where(
                    phase2_account_lease_releases.c.lease_sha256 == recovered.semantic_sha256
                )
            )
            .mappings()
            .all()
        )
    assert len(releases) == 1
    assert recovered.owner_id.startswith("offline-owner-")
    assert recovered.policy_sha256 == configuration.lease_policy().semantic_sha256
