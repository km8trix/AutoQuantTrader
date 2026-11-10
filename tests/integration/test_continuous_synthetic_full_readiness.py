"""Fresh full-schema component checks, not application or host readiness.

The original verifier keeps its default Phase 0 prerequisite and all original
continuous validators. Only disposable migrated stores and modeled inputs are
used; no operator, process, source enrollment or execution authority is added.
"""

from datetime import timedelta
from decimal import Decimal
from hashlib import sha256

import pytest
import sqlalchemy as sa

from packages.application import personal_codec
from packages.domain.account_coordinator import AccountLeasePolicy
from packages.domain.operational_control import OperationalControlState
from packages.domain.walking_thread import WalkingThread
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_integrity import SqlContinuousIntegrityReader
from packages.persistence.database import DatabaseSchemaNotReady, verify_operational_schema
from packages.persistence.risk import SqlRiskDecisionRepository
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from packages.persistence.schema import (
    ledger_entries,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
)
from packages.persistence.walking_thread import WalkingThreadUnitOfWork
from tests.integration.test_continuous_synthetic_offline_configuration import (
    _release_setup,
    _study,
)


def _seed_phase_zero(study):
    engine = study.ports["account_engine"]
    result = WalkingThread.run(SqlRiskDecisionRepository(engine, WalkingThread.risk_authority()))
    WalkingThreadUnitOfWork(engine).persist(result)
    assert result.risk_account_snapshot.account_id == WalkingThread.account_id
    assert result.risk_account_snapshot.account_id != study.genesis.scope.account_id
    assert result.account.cash == Decimal("98989.00")
    assert result.account.equity == Decimal("99999.00")
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(ledger_entries)
                .where(ledger_entries.c.event_type == "opening_balance")
            )
            == 1
        )


def _reader(study):
    owners = study.owners
    journals = (
        owners.account.journal,
        owners.runtime.publisher.journal,
        owners.venue_sources.journal,
        owners.runtime.journal,
        owners.runtime.forward_sources.journal,
        owners.runtime.operating.journal,
        owners.owners.commands.journal,
    )
    engine = study.ports["account_engine"]
    assert len(journals) == 7
    assert all(journal._engine is engine for journal in journals)
    assert study.ports["venue_engine"] is not engine
    return SqlContinuousIntegrityReader(
        engine,
        scope=study.genesis.scope,
        reconciliation_scope=owners.venue_sources.scope,
        account=owners.account,
        daily=owners.daily,
        publisher=owners.runtime.publisher,
        associations=SqlRuntimeOwnerAssociations(owner_dependencies=owners.owners),
        journals=journals,
        fence=study.lease.fence,
    )


def _all_rows(engine):
    # Reflect the actual fresh application tables, including alembic_version.
    # This compares SQL row values, not physical SQLite/internal storage bytes.
    with engine.connect() as connection:
        reflected = sa.MetaData()
        reflected.reflect(bind=connection)
        return tuple(
            (
                name,
                tuple(
                    tuple(row)
                    for row in connection.execute(
                        sa.select(table).order_by(
                            *(tuple(table.primary_key.columns) or tuple(table.columns))
                        )
                    )
                ),
            )
            for name, table in sorted(reflected.tables.items())
        )


def _facts(study):
    # Every object here belongs to this fixture's two explicit private stores.
    # No parent directory, retained account or unrelated runtime is inspected.
    objects = tuple(
        tuple(sorted((path.name, path.read_bytes()) for path in study.paths[key].iterdir()))
        for key in ("artifact_root", "venue_artifact_root")
    )
    return (
        _all_rows(study.ports["account_engine"]),
        _all_rows(study.ports["venue_engine"]),
        objects,
    )


def _assert_scopes_closed(reader):
    assert reader.account.coordinator._state.observations is None
    assert reader._factory_read is None
    assert reader._daily_episode is None
    assert reader.composer._integrity_daily is None
    assert reader.composer._integrity_daily_active is None


def _assert_held(study, lease):
    assert study.genesis.account.coordinator.current() == lease
    assert lease.fencing_generation == 2
    assert lease.revision_number == 1
    assert lease.previous_lease_sha256 is None
    assert lease.heartbeat_at == lease.acquired_at
    assert lease.expires_at - lease.acquired_at == timedelta(seconds=60)
    assert (
        lease.policy_sha256
        == AccountLeasePolicy(
            "synthetic-session-account-lease/1",
            "1",
            timedelta(seconds=60),
            timedelta(seconds=5),
            timedelta(seconds=10),
        ).semantic_sha256
    )
    assert study.genesis.release.fence == study.genesis.lease.fence
    assert study.genesis.release.lease_sha256 == study.genesis.lease.semantic_sha256
    with study.ports["account_engine"].connect() as connection:
        head = connection.execute(sa.select(phase2_account_lease_heads)).mappings().one()
        assert head["account_id"] == lease.account_id
        assert head["last_fencing_generation"] == head["current_fencing_generation"] == 2
        assert head["current_lease_sha256"] == lease.semantic_sha256
        assert connection.scalar(sa.select(sa.func.count()).select_from(phase2_account_leases)) == 2
        releases = tuple(connection.execute(sa.select(phase2_account_lease_releases)).mappings())
        assert len(releases) == 1
        assert releases[0]["lease_sha256"] == study.genesis.lease.semantic_sha256


def _assert_released(study, lease):
    assert study.lease is None
    assert study.genesis.account.coordinator.current() is None
    with study.ports["account_engine"].connect() as connection:
        head = connection.execute(sa.select(phase2_account_lease_heads)).mappings().one()
        assert head["last_fencing_generation"] == 2
        assert head["current_fencing_generation"] is None
        assert head["current_lease_sha256"] is None
        assert connection.scalar(sa.select(sa.func.count()).select_from(phase2_account_leases)) == 2
        releases = tuple(connection.execute(sa.select(phase2_account_lease_releases)).mappings())
        assert len(releases) == 2
        assert {row["lease_sha256"] for row in releases} == {
            study.genesis.lease.semantic_sha256,
            lease.semantic_sha256,
        }
        released = next(row for row in releases if row["lease_sha256"] == lease.semantic_sha256)
        assert released["owner_id"] == lease.owner_id
        assert released["lease_id"] == lease.lease_id
        assert released["fencing_generation"] == lease.fencing_generation
        assert released["policy_sha256"] == lease.policy_sha256
    assert study.genesis.account.coordinator._state.observations is None


def _assert_initial_state(study, *, installed):
    genesis = study.genesis
    checkpoint = genesis.restored.checkpoint
    spec = checkpoint.inputs.spec
    assert genesis.restored.receipt.commit.sequence == 1
    assert genesis.restored.request == checkpoint.inputs
    assert spec.initial_cash == Decimal("10000")
    assert spec.live_authorized is False
    assert spec.environment == "stateful_simulation"
    assert spec.source_mode == "synthetic_observed"
    assert spec.risk_policy.policy_id == "personal-daily-stateful-simulation/1"
    assert spec.execution_policy.model_id == "observed-facts-v1"
    assert len(checkpoint.state.cash_flows) == 1
    assert checkpoint.state.cash_flows[0].amount == Decimal("10000")
    assert not checkpoint.state.submissions
    assert not checkpoint.state.broker_events
    assert not checkpoint.state.commitments
    assert not checkpoint.runtime_decisions
    inventory = study.owners.daily.resolve_snapshot(
        study.owners.daily.read_snapshot(
            account_id=genesis.scope.account_id, fence=study.lease.fence
        )
    )
    assert inventory.control == genesis.control
    assert inventory.control.effective_state is OperationalControlState.HALTED
    assert inventory.control.sequence_number == 1
    assert inventory.control.active_operation is None
    assert not inventory.admissions
    assert not inventory.obligations.bindings
    assert not inventory.attempts
    assert not inventory.attempt_envelopes
    assert not inventory.observed_groups
    if installed:
        assignment = inventory.assignment
        assert assignment == study.assignment
        assert inventory.assignment_rows == (assignment,)
        assert assignment.generation == 1
        assert assignment.previous_assignment_sha256 is None
        assert assignment.enabled_for_new_exposure is False
        assert assignment.live_authorized is False
        assert assignment.policy == spec.risk_policy
        assert assignment.strategy == spec.strategy
    else:
        assert inventory.assignment is None
        assert not inventory.assignment_rows
    venue = genesis.venue.read()
    assert venue.head.sequence == 1
    assert venue.state.sequence == 0
    assert not venue.state.commands
    assert not venue.state.acknowledgments
    assert not venue.state.accounting.submissions
    assert not venue.state.accounting.commitments
    assert venue.state.accounting.cash_flows == checkpoint.state.cash_flows
    assert genesis.venue.model.live_authorized is False
    assert genesis.venue.model.source_mode == "synthetic_fixture"
    with study.ports["account_engine"].connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(continuous_account_commits))
            == 1
        )


@pytest.mark.parametrize("installed", [False, True], ids=["empty_b", "disabled_generation1"])
def test_full_default_schema_accepts_genuine_halted_history(tmp_path, installed):
    with _study(tmp_path, install=installed) as study:
        _seed_phase_zero(study)
        reader = _reader(study)
        lease = study.lease
        _assert_initial_state(study, installed=installed)
        _assert_held(study, lease)
        _assert_scopes_closed(reader)
        before = _facts(study)
        instant = study.ports["clock"].now()

        # Omit require_phase_zero_facts: this is the full original default True.
        assert (
            verify_operational_schema(
                study.ports["account_engine"],
                research_codec=personal_codec,
                continuous_integrity=reader,
            )
            is None
        )

        assert _facts(study) == before
        assert study.ports["clock"].now() == instant
        _assert_scopes_closed(reader)
        _assert_held(study, lease)
        _release_setup(study)
        _assert_released(study, lease)


def test_full_default_schema_requires_actual_reader_for_nonempty_history(tmp_path):
    with _study(tmp_path, install=False) as study:
        _seed_phase_zero(study)
        reader = _reader(study)
        lease = study.lease
        _assert_initial_state(study, installed=False)
        _assert_held(study, lease)
        before = _facts(study)

        with pytest.raises(
            DatabaseSchemaNotReady,
            match=r"^nonempty continuous history requires an integrity reader$",
        ):
            verify_operational_schema(study.ports["account_engine"], research_codec=personal_codec)

        assert _facts(study) == before
        _assert_scopes_closed(reader)
        _assert_held(study, lease)
        _release_setup(study)
        _assert_released(study, lease)


def test_full_default_schema_preserves_required_opening_balance_prerequisite(tmp_path):
    with _study(tmp_path, install=False) as study:
        reader = _reader(study)
        lease = study.lease
        _assert_initial_state(study, installed=False)
        _assert_held(study, lease)
        with study.ports["account_engine"].connect() as connection:
            assert (
                connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(ledger_entries)
                    .where(ledger_entries.c.event_type == "opening_balance")
                )
                == 0
            )
        before = _facts(study)

        with pytest.raises(
            DatabaseSchemaNotReady, match=r"^operational database integrity verification failed$"
        ):
            verify_operational_schema(
                study.ports["account_engine"],
                research_codec=personal_codec,
                continuous_integrity=reader,
            )

        assert _facts(study) == before
        _assert_scopes_closed(reader)
        _assert_held(study, lease)
        _release_setup(study)
        _assert_released(study, lease)


def test_full_default_schema_denies_damage_to_actual_referenced_closure(tmp_path):
    with _study(tmp_path, install=False) as study:
        _seed_phase_zero(study)
        reader = _reader(study)
        lease = study.lease
        _assert_initial_state(study, installed=False)
        _assert_held(study, lease)
        reference = study.genesis.restored.receipt.commit.source_evidence.object_ref
        original = study.ports["account_artifacts"].read(reference)
        assert original and len(original) == reference.byte_count
        assert sha256(original).hexdigest() == reference.object_sha256
        target = study.paths["artifact_root"] / (reference.object_sha256 + ".json")
        assert target.read_bytes() == original
        damaged = original[:-1] + bytes((original[-1] ^ 1,))
        assert len(damaged) == len(original) and damaged != original
        assert target.write_bytes(damaged) == reference.byte_count
        before = _facts(study)  # Adverse preparation is part of the retained baseline.

        with pytest.raises(
            DatabaseSchemaNotReady, match=r"^continuous retained integrity verification failed$"
        ):
            verify_operational_schema(
                study.ports["account_engine"],
                research_codec=personal_codec,
                continuous_integrity=reader,
            )

        assert _facts(study) == before
        assert target.read_bytes() == damaged
        _assert_scopes_closed(reader)
        _assert_held(study, lease)
        _release_setup(study)
        _assert_released(study, lease)


def test_full_default_schema_denies_reader_with_explicitly_released_fence(tmp_path):
    with _study(tmp_path, install=False) as study:
        _seed_phase_zero(study)
        reader = _reader(study)
        lease = study.lease
        _assert_initial_state(study, installed=False)
        _assert_held(study, lease)
        _release_setup(study)
        _assert_released(study, lease)
        before = _facts(study)

        with pytest.raises(
            DatabaseSchemaNotReady, match=r"^continuous retained integrity verification failed$"
        ):
            verify_operational_schema(
                study.ports["account_engine"],
                research_codec=personal_codec,
                continuous_integrity=reader,
            )

        assert _facts(study) == before
        _assert_scopes_closed(reader)
        _assert_released(study, lease)
        # _study sees lease=None and never issues a second release or reacquires.
