"""Fixed offline graph restores real retained signed history from a migrated database."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from alembic import command
from fastapi import HTTPException

from apps.trader.continuous_simulation_factory import (
    CONFIGURATION_SCHEMA,
    PRODUCER_MAP_SCHEMA,
    ContinuousSimulationConfiguration,
    ContinuousSimulationFactory,
    ContinuousSimulationFactoryError,
    load_continuous_configuration,
    run_continuous_operation,
)
from packages.application import personal_codec as codec
from packages.application.continuous_process import ContinuousProcessRequest
from packages.domain.continuous_persistence_contracts import CONTINUOUS_REQUEST_SCHEMA
from packages.persistence.database import EXPECTED_SCHEMA_REVISION
from tests.integration.test_personal_research_migration import migration_config
from tests.integration.test_runtime_owner_associations import (
    genuine_empty_b_bootstrap,
    install_initial_signed_assignment,
)


@pytest.fixture
def configured(tmp_path, monkeypatch):
    tmp_path = tmp_path.resolve()
    path = tmp_path / "account.sqlite"
    migration = migration_config(path)
    migration.attributes["aqt_explicit_database_url"] = f"sqlite+pysqlite:///{path}"
    command.upgrade(migration, EXPECTED_SCHEMA_REVISION)
    fixture = genuine_empty_b_bootstrap(tmp_path, monkeypatch)
    pair, _owners, producer, *_ = fixture
    try:
        config = ContinuousSimulationConfiguration(
            schema_id=CONFIGURATION_SCHEMA,
            operation="restore",
            owner_id="actual-offline-restorer",
            database_path=str(path),
            artifact_root=str(tmp_path / "objects"),
            venue_database_path=str(tmp_path / "independent.sqlite"),
            venue_artifact_root=str(tmp_path / "independent-objects"),
            inputs=pair.base.put(CONTINUOUS_REQUEST_SCHEMA, pair.base.inputs),
            venue_model=pair.base.put("venue-model/1", pair.model),
            producer_map=pair.base.put(PRODUCER_MAP_SCHEMA, producer.producer_map),
            benchmark_instrument_id=producer.benchmark_instrument_id,
            capture_evidence_class=pair.base.forward.evidence_class,
            clock_profile=producer.operating.clock_sampler.profile,
            lease_policy_id="fixture",
            lease_policy_version="1",
            lease_ttl_microseconds=60_000_000,
            maximum_in_flight_microseconds=5_000_000,
            takeover_safety_microseconds=10_000_000,
        )
        for database in (path, tmp_path / "independent.sqlite"):
            database.chmod(0o600)
        yield fixture, config
    finally:
        pair.close()


def request_for(fixture, config):
    pair = fixture[0]
    path = Path(config.database_path).parent / "offline.json"
    path.write_bytes(codec.encode_record(config))
    path.chmod(0o600)
    return ContinuousProcessRequest(
        account_id=pair.base.scope.account_id,
        operation_id="restore-original-offline-history",
        configuration_path=path,
        objects=tuple(reference.object_ref for reference in config.references),
    )


def release(fixture):
    h = fixture[0].base.h
    h.coordinator.release(h.lease.fence)


def test_fixed_factory_restores_actual_signed_bootstrap_and_preserves_financial_rows(configured):
    fixture, config = configured
    pair = fixture[0]
    install_initial_signed_assignment(fixture)
    original = pair.account.restore(pair.base.scope)
    counts = pair.counts()
    release(fixture)
    request = request_for(fixture, config)
    first = run_continuous_operation(request, stop_requested=lambda: False)
    result = json.loads(first)
    assert result["status"] == "restored"
    assert result["sequence"] == 1 and result["assignment_generation"] == 1
    assert result["checkpoint_sha256"] == original.checkpoint.semantic_sha256
    assert str(Path(config.database_path).parent).encode() not in first
    assert pair.counts() == counts
    # New real leases do not alter original source identity or authorize an action.
    assert run_continuous_operation(request, stop_requested=lambda: False) == first
    assert pair.counts() == counts


def test_fixed_factory_disabled_auth_cannot_reauthenticate_original_owner_cookie(configured):
    fixture, config = configured
    _dep, original_command, *_ = install_initial_signed_assignment(fixture)
    release(fixture)
    factory = ContinuousSimulationFactory(
        config, account_id=fixture[0].base.scope.account_id, stop_requested=lambda: False
    )
    try:
        cookie, csrf = fixture[-2:]
        with pytest.raises(HTTPException):
            factory.commands.authenticator.authenticate(
                original_command,
                session_cookie=cookie,
                csrf_token=csrf,
                now=original_command.requested_at,
            )
        assert json.loads(factory.execute(operation_id="verify-original-owner"))["sequence"] == 1
    finally:
        factory.close()


def test_fixed_factory_never_seeds_missing_owner_assignment(configured):
    fixture, config = configured
    release(fixture)
    before = fixture[0].counts()
    with pytest.raises(ContinuousSimulationFactoryError, match="OFFLINE_OPERATION_FAILED"):
        run_continuous_operation(request_for(fixture, config), stop_requested=lambda: False)
    assert fixture[0].counts() == before


@pytest.mark.parametrize("change", ["shared_database", "shared_objects", "absent_database"])
def test_fixed_factory_rejects_nonindependent_or_missing_storage_without_creating_it(
    configured, change
):
    fixture, config = configured
    altered = (
        replace(config, venue_database_path=config.database_path)
        if change == "shared_database"
        else replace(config, venue_artifact_root=config.artifact_root)
        if change == "shared_objects"
        else replace(
            config, database_path=str(Path(config.database_path).parent / "missing.sqlite")
        )
    )
    with pytest.raises(
        ContinuousSimulationFactoryError, match="OFFLINE_FACTORY_INITIALIZATION_FAILED"
    ):
        ContinuousSimulationFactory(
            altered, account_id=fixture[0].base.scope.account_id, stop_requested=lambda: False
        )
    assert not (Path(config.database_path).parent / "missing.sqlite").exists()


def test_fixed_factory_stops_before_storage_or_lease_acquisition(configured):
    fixture, config = configured
    before = fixture[0].counts()
    with pytest.raises(ContinuousSimulationFactoryError):
        run_continuous_operation(request_for(fixture, config), stop_requested=lambda: True)
    assert fixture[0].counts() == before


def test_fixed_configuration_rejects_arbitrary_operation(configured):
    with pytest.raises(ContinuousSimulationFactoryError):
        replace(configured[1], operation="dispatch")


def test_configuration_gate_rejects_env_named_path_before_read(tmp_path, monkeypatch):
    import apps.trader.continuous_simulation_factory as factory

    def forbidden(*args, **kwargs):
        pytest.fail("a rejected configuration path must not be read")

    monkeypatch.setattr(factory, "_private_read", forbidden)
    with pytest.raises(ContinuousSimulationFactoryError, match="OFFLINE_CONFIGURATION_INVALID"):
        load_continuous_configuration(tmp_path / ".env-unread-fixture.json")


def test_configuration_gate_rejects_nonprivate_payload(tmp_path):
    path = tmp_path / "unreadable-configuration.json"
    path.write_bytes(b'{"module":"arbitrary"}')
    path.chmod(0o644)
    with pytest.raises(ContinuousSimulationFactoryError, match="OFFLINE_CONFIGURATION_INVALID"):
        load_continuous_configuration(path)


def test_factory_rejects_mutated_original_configuration_before_readiness(configured):
    fixture, config = configured
    release(fixture)
    factory = ContinuousSimulationFactory(
        config, account_id=fixture[0].base.scope.account_id, stop_requested=lambda: False
    )
    try:
        object.__setattr__(config, "operation", "dispatch")
        with pytest.raises(ContinuousSimulationFactoryError, match="OFFLINE_OPERATION_FAILED"):
            factory.execute(operation_id="unchanged-operation")
    finally:
        object.__setattr__(config, "operation", "restore")
        factory.close()


def test_direct_factories_with_same_worker_label_cannot_adopt_or_release_peer_lease(configured):
    fixture, config = configured
    install_initial_signed_assignment(fixture)
    release(fixture)
    account_id = fixture[0].base.scope.account_id
    first = ContinuousSimulationFactory(config, account_id=account_id, stop_requested=lambda: False)
    try:
        original_fence = first.lease.fence
        assert original_fence.owner_id != config.owner_id
        with pytest.raises(ContinuousSimulationFactoryError):
            ContinuousSimulationFactory(config, account_id=account_id, stop_requested=lambda: False)
        # Failed construction had no lease of its own to release.
        assert first.coordinator.revalidate(original_fence).fence == original_fence
    finally:
        first.close()
    restarted = ContinuousSimulationFactory(
        config, account_id=account_id, stop_requested=lambda: False
    )
    try:
        assert restarted.lease.fence.owner_id != original_fence.owner_id
        assert restarted.lease.fence.fencing_generation == original_fence.fencing_generation + 1
    finally:
        restarted.close()
