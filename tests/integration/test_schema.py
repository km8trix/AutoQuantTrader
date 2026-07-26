from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from packages.domain.account_coordinator import (
    ACCOUNT_COORDINATOR_CONTRACT_VERSION,
    ACCOUNT_LEASE_CONTRACT_VERSION,
    AccountCoordinatorError,
    AccountLease,
    AccountLeasePolicy,
    _account_lease_release,
    _legacy_account_lease,
)
from packages.domain.batch_risk import BatchRiskDecisionStatus
from packages.domain.canonical import canonical_json_text
from packages.domain.clock import FixedClock
from packages.domain.identifiers import canonical_id
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
    account_lease_from_row,
    account_lease_release_from_row,
    immutable_account_lease_release_values,
    immutable_account_lease_values,
)
from packages.persistence.batch_risk import (
    LEGACY_CAPACITY_OBSERVATION_CONTRACT,
    _decision_fact_payload,
    _decode_active_capacity,
    load_batch_risk_decision,
)
from packages.persistence.database import (
    EXPECTED_SCHEMA_REVISION,
    _verify_phase2_durability_integrity,
    create_database_engine,
)
from packages.persistence.reservation_lifecycle import SqlReservationLifecycleRepository
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase2_batch_decisions,
    phase2_ledger_entries,
    phase2_ledger_postings,
    phase2_order_events,
    phase2_reservation_release_events,
    phase2_simulation_horizon_facts,
    phase2_submission_attempt_events,
)
from tests.integration.test_phase2_batch_risk_persistence import _repository
from tests.unit.test_batch_risk import (
    EVALUATED_AT,
    MutableClock,
    make_batch,
    make_portfolio,
    snapshot,
)

ROOT = Path(__file__).resolve().parents[2]
PHASE2_TABLE_NAMES = frozenset(
    {
        "phase2_account_lease_heads",
        "phase2_account_lease_releases",
        "phase2_account_leases",
        "phase2_authorization_consumptions",
        "phase2_backtest_audit_events",
        "phase2_backtest_fixtures",
        "phase2_backtest_job_events",
        "phase2_backtest_job_heads",
        "phase2_backtest_jobs",
        "phase2_backtest_reports",
        "phase2_backtest_run_manifests",
        "phase2_batch_authorizations",
        "phase2_batch_decisions",
        "phase2_batch_members",
        "phase2_batch_reservations",
        "phase2_ledger_entries",
        "phase2_ledger_postings",
        "phase2_logical_orders",
        "phase2_order_events",
        "phase2_reservation_release_events",
        "phase2_simulation_horizon_facts",
        "phase2_submission_attempt_events",
        "phase2_submission_attempts",
        "phase2_strategy_configurations",
        "phase2_strategy_versions",
    }
)
PHASE3_TABLE_NAMES = frozenset(
    {
        "phase3_experiment_attempt_events",
        "phase3_experiment_attempts",
        "phase3_experiment_audit_events",
        "phase3_experiment_families",
        "phase3_experiment_tape_claims",
        "phase3_experiment_tape_policies",
        "phase3_holdout_reveals",
    }
)


def _legacy_lease_values(lease: AccountLease) -> dict[str, object]:
    assert lease.contract_version == ACCOUNT_COORDINATOR_CONTRACT_VERSION
    return {
        "lease_sha256": lease.semantic_sha256,
        "account_id": lease.account_id,
        "owner_id": lease.owner_id,
        "lease_id": lease.lease_id,
        "fencing_generation": lease.fencing_generation,
        "acquired_at": lease.acquired_at,
        "heartbeat_at": lease.heartbeat_at,
        "expires_at": lease.expires_at,
        "policy_sha256": lease.policy_sha256,
        "canonical_payload": canonical_json_text(
            (
                ACCOUNT_COORDINATOR_CONTRACT_VERSION,
                "lease",
                lease.account_id,
                lease.owner_id,
                lease.lease_id,
                lease.fencing_generation,
                lease.acquired_at,
                lease.heartbeat_at,
                lease.expires_at,
                lease.policy_sha256,
            )
        ),
    }


def _legacy_lease_pair(
    *,
    account_id: str,
    owner_id: str,
    acquired_at: datetime,
    policy_sha256: str,
) -> tuple[AccountLease, AccountLease]:
    lease_id = canonical_id(
        "account-coordinator-lease",
        account_id,
        1,
        owner_id,
        acquired_at,
        policy_sha256,
    )
    first = _legacy_account_lease(
        account_id=account_id,
        owner_id=owner_id,
        lease_id=lease_id,
        fencing_generation=1,
        revision_number=1,
        previous_lease_sha256=None,
        acquired_at=acquired_at,
        heartbeat_at=acquired_at,
        expires_at=acquired_at + timedelta(seconds=30),
        policy_sha256=policy_sha256,
    )
    second = _legacy_account_lease(
        account_id=account_id,
        owner_id=owner_id,
        lease_id=lease_id,
        fencing_generation=1,
        revision_number=2,
        previous_lease_sha256=first.semantic_sha256,
        acquired_at=acquired_at,
        heartbeat_at=acquired_at + timedelta(seconds=10),
        expires_at=acquired_at + timedelta(seconds=40),
        policy_sha256=policy_sha256,
    )
    return first, second


def test_operational_schema_can_be_created_without_postgresql() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")

    metadata.create_all(engine)

    assert set(inspect(engine).get_table_names()) == {
        "calendar_sessions",
        "calendar_versions",
        "corporate_action_revisions",
        "corporate_action_set_members",
        "corporate_action_sets",
        "data_objects",
        "data_quality_issues",
        "data_quality_runs",
        "dataset_manifest_partitions",
        "dataset_manifests",
        "dataset_partitions",
        "fills",
        "ingestion_jobs",
        "instrument_identifiers",
        "instruments",
        "ledger_entries",
        "ledger_postings",
        "market_data_admission_checks",
        "market_data_admission_profiles",
        "market_data_admission_runs",
        "market_data_entitlements",
        "market_data_sources",
        "orders",
        "partition_quarantines",
        "phase2_account_lease_heads",
        "phase2_account_lease_releases",
        "phase2_account_leases",
        "phase2_authorization_consumptions",
        "phase2_backtest_audit_events",
        "phase2_backtest_fixtures",
        "phase2_backtest_job_events",
        "phase2_backtest_job_heads",
        "phase2_backtest_jobs",
        "phase2_backtest_reports",
        "phase2_backtest_run_manifests",
        "phase2_batch_authorizations",
        "phase2_batch_decisions",
        "phase2_batch_members",
        "phase2_batch_reservations",
        "phase2_ledger_entries",
        "phase2_ledger_postings",
        "phase2_logical_orders",
        "phase2_order_events",
        "phase2_reservation_release_events",
        "phase2_simulation_horizon_facts",
        "phase2_submission_attempt_events",
        "phase2_submission_attempts",
        "phase2_strategy_configurations",
        "phase2_strategy_versions",
        "phase3_experiment_attempt_events",
        "phase3_experiment_attempts",
        "phase3_experiment_audit_events",
        "phase3_experiment_families",
        "phase3_experiment_tape_claims",
        "phase3_experiment_tape_policies",
        "phase3_holdout_reveals",
        "risk_account_guards",
        "risk_decisions",
        "risk_reservations",
        "replay_run_manifests",
        "submission_attempts",
        "universe_memberships",
        "universe_versions",
    }


def test_readiness_revision_pin_matches_the_single_alembic_head() -> None:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))

    assert ScriptDirectory.from_config(config).get_current_head() == EXPECTED_SCHEMA_REVISION


def test_index_backed_constraint_names_are_schema_wide_unique() -> None:
    """PostgreSQL places indexes for primary/unique constraints in one namespace."""

    owners: dict[str, list[str]] = {}
    for table in metadata.tables.values():
        index_backed = [
            constraint
            for constraint in table.constraints
            if isinstance(constraint, sa.PrimaryKeyConstraint | sa.UniqueConstraint)
        ]
        for schema_item in (*index_backed, *table.indexes):
            name = schema_item.name
            assert isinstance(name, str)
            owners.setdefault(name, []).append(table.name)

    assert {name: table_names for name, table_names in owners.items() if len(table_names) > 1} == {}


def test_simulation_horizon_schema_preserves_exact_proof_bindings() -> None:
    assert tuple(phase2_simulation_horizon_facts.c.keys()) == (
        "horizon_id",
        "horizon_reference",
        "horizon_source_sha256",
        "reservation_id",
        "parent_decision_id",
        "authorization_id",
        "attempt_id",
        "order_id",
        "final_order_event_id",
        "replay_run_id",
        "replay_manifest_sha256",
        "replay_event_count",
        "replay_watermark_count",
        "simulation_result_id",
        "horizon_at",
        "recorded_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase2_simulation_horizon_facts.foreign_key_constraints
    } == {
        ("phase2_batch_reservations.reservation_id",),
        ("phase2_batch_decisions.decision_id",),
        ("phase2_batch_authorizations.authorization_id",),
        ("phase2_submission_attempts.attempt_id",),
        ("phase2_logical_orders.order_id",),
        ("phase2_order_events.event_id",),
        ("replay_run_manifests.run_id",),
        ("replay_run_manifests.manifest_sha256",),
    }
    assert {index.name for index in phase2_simulation_horizon_facts.indexes} == {
        "ix_phase2_simulation_horizon_facts_reservation_recorded"
    }


def test_account_lease_schema_preserves_gap_free_revision_bindings() -> None:
    assert tuple(phase2_account_leases.c.keys()) == (
        "lease_sha256",
        "account_id",
        "owner_id",
        "lease_id",
        "fencing_generation",
        "revision_number",
        "previous_lease_sha256",
        "acquired_at",
        "heartbeat_at",
        "expires_at",
        "policy_sha256",
        "canonical_payload",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase2_account_leases.foreign_key_constraints
    } == {
        (
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        )
    }
    assert {
        tuple(column.name for column in constraint.columns)
        for constraint in phase2_account_leases.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    } >= {
        ("account_id", "fencing_generation", "lease_sha256"),
        ("account_id", "fencing_generation", "revision_number"),
    }


def test_phase2_durability_migration_is_additive_and_reversible(tmp_path: Path) -> None:
    database_path = tmp_path / "phase2-durability.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "0006_replay_run_manifests")
    engine = create_engine(database_url)
    legacy_tables = set(inspect(engine).get_table_names())
    legacy_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in legacy_tables
    }

    command.upgrade(config, "head")

    upgraded_tables = set(inspect(engine).get_table_names())
    assert upgraded_tables == legacy_tables | PHASE2_TABLE_NAMES | PHASE3_TABLE_NAMES
    assert {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in legacy_tables
    } == legacy_columns
    upgraded_inspector = inspect(engine)
    migrated_lease_columns = {
        column["name"]: column for column in upgraded_inspector.get_columns("phase2_account_leases")
    }
    assert set(migrated_lease_columns) == set(phase2_account_leases.c.keys())
    assert migrated_lease_columns["revision_number"]["nullable"] is False
    assert migrated_lease_columns["previous_lease_sha256"]["nullable"] is True
    assert any(
        foreign_key["constrained_columns"]
        == ["account_id", "fencing_generation", "previous_lease_sha256"]
        and foreign_key["referred_columns"] == ["account_id", "fencing_generation", "lease_sha256"]
        for foreign_key in upgraded_inspector.get_foreign_keys("phase2_account_leases")
    )
    assert {
        tuple(constraint["column_names"])
        for constraint in upgraded_inspector.get_unique_constraints("phase2_account_leases")
    } >= {
        ("account_id", "fencing_generation", "lease_sha256"),
        ("account_id", "fencing_generation", "revision_number"),
        ("account_id", "lease_id", "heartbeat_at"),
    }
    assert {
        index["name"]: tuple(index["column_names"])
        for index in upgraded_inspector.get_indexes("phase2_account_leases")
    }["ix_phase2_account_leases_account_generation"] == (
        "account_id",
        "fencing_generation",
        "revision_number",
    )

    engine.dispose()
    command.downgrade(config, "0006_replay_run_manifests")
    downgraded_engine = create_engine(database_url)
    assert set(inspect(downgraded_engine).get_table_names()) == legacy_tables
    downgraded_engine.dispose()


def test_phase3_governance_migration_is_additive_and_reversible(tmp_path: Path) -> None:
    database_path = tmp_path / "phase3-governance.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "0009_lease_revision_chain")
    engine = create_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    }

    command.upgrade(config, "head")

    assert set(inspect(engine).get_table_names()) == prior_tables | PHASE3_TABLE_NAMES
    assert {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    engine.dispose()
    command.downgrade(config, "0009_lease_revision_chain")
    downgraded_engine = create_engine(database_url)
    assert set(inspect(downgraded_engine).get_table_names()) == prior_tables
    downgraded_engine.dispose()


def test_lease_revision_upgrade_preserves_v1_history_and_transitions_to_v2(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "lease-revision-upgrade.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0008_phase2_research")
    engine = create_engine(database_url)

    assert "revision_number" not in {
        column["name"] for column in inspect(engine).get_columns("phase2_account_leases")
    }
    base = datetime(2026, 7, 20, 13, 30, tzinfo=UTC)
    policy = AccountLeasePolicy(
        policy_id="phase2-upgrade-coordinator",
        policy_version="1.0.0",
        lease_ttl=timedelta(seconds=30),
        maximum_in_flight_duration=timedelta(seconds=5),
        takeover_safety_interval=timedelta(seconds=10),
    )
    released_first, released_second = _legacy_lease_pair(
        account_id="legacy-released-account",
        owner_id="legacy-worker-a",
        acquired_at=base,
        policy_sha256=policy.semantic_sha256,
    )
    active_first, active_second = _legacy_lease_pair(
        account_id="legacy-active-account",
        owner_id="legacy-worker-b",
        acquired_at=base,
        policy_sha256=policy.semantic_sha256,
    )
    release = _account_lease_release(
        fence=released_second.fence,
        released_at=base + timedelta(seconds=15),
        policy_sha256=policy.semantic_sha256,
        lease_sha256=released_second.semantic_sha256,
    )
    legacy_leases = sa.table(
        "phase2_account_leases",
        sa.column("lease_sha256", sa.String(64)),
        sa.column("account_id", sa.String(64)),
        sa.column("owner_id", sa.String(128)),
        sa.column("lease_id", sa.String(64)),
        sa.column("fencing_generation", sa.BigInteger()),
        sa.column("acquired_at", sa.DateTime(timezone=True)),
        sa.column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.column("expires_at", sa.DateTime(timezone=True)),
        sa.column("policy_sha256", sa.String(64)),
        sa.column("canonical_payload", sa.Text()),
    )
    with engine.begin() as connection:
        connection.execute(
            sa.insert(legacy_leases),
            [
                _legacy_lease_values(active_second),
                _legacy_lease_values(released_second),
                _legacy_lease_values(active_first),
                _legacy_lease_values(released_first),
            ],
        )
        connection.execute(
            sa.insert(phase2_account_lease_heads),
            [
                {
                    "account_id": active_second.account_id,
                    "last_fencing_generation": 1,
                    "current_fencing_generation": 1,
                    "current_lease_sha256": active_second.semantic_sha256,
                    "updated_at": active_second.heartbeat_at,
                },
                {
                    "account_id": released_second.account_id,
                    "last_fencing_generation": 1,
                    "current_fencing_generation": None,
                    "current_lease_sha256": None,
                    "updated_at": release.released_at,
                },
            ],
        )
        connection.execute(
            sa.insert(phase2_account_lease_releases),
            immutable_account_lease_release_values(release),
        )

    command.upgrade(config, "head")

    with engine.connect() as connection:
        upgraded_rows = tuple(
            connection.execute(
                sa.select(phase2_account_leases).order_by(
                    phase2_account_leases.c.account_id,
                    phase2_account_leases.c.revision_number,
                )
            ).mappings()
        )
        decoded = tuple(account_lease_from_row(row) for row in upgraded_rows)
        release_row = connection.execute(sa.select(phase2_account_lease_releases)).mappings().one()
    assert decoded == (active_first, active_second, released_first, released_second)
    assert [lease.revision_number for lease in decoded] == [1, 2, 1, 2]
    assert [lease.previous_lease_sha256 for lease in decoded] == [
        None,
        active_first.semantic_sha256,
        None,
        released_first.semantic_sha256,
    ]
    assert account_lease_release_from_row(release_row) == release
    with pytest.raises(AccountCoordinatorError, match="requires the v2 contract"):
        immutable_account_lease_values(active_first)

    command.downgrade(config, "0008_phase2_research")
    downgraded_columns = {
        column["name"] for column in inspect(engine).get_columns("phase2_account_leases")
    }
    assert "revision_number" not in downgraded_columns
    assert "previous_lease_sha256" not in downgraded_columns
    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(legacy_leases)) == 4
        assert (
            connection.scalar(
                sa.select(phase2_account_lease_heads.c.current_lease_sha256).where(
                    phase2_account_lease_heads.c.account_id == active_second.account_id
                )
            )
            == active_second.semantic_sha256
        )
        assert (
            connection.scalar(sa.select(phase2_account_lease_releases.c.release_sha256))
            == release.semantic_sha256
        )

    command.upgrade(config, "head")
    authority = SqlAccountCoordinatorAuthority(
        engine=engine,
        policy=policy,
        clock=FixedClock(base + timedelta(seconds=20)),
    )
    active = SqlAccountCoordinator(
        account_id=active_second.account_id,
        authority=authority,
    )
    released = SqlAccountCoordinator(
        account_id=released_second.account_id,
        authority=authority,
    )
    assert active.current() == active_second
    assert released.current() is None

    renewed = active.renew(active_second.fence)
    reacquired = released.acquire("post-upgrade-worker")

    assert renewed.contract_version == ACCOUNT_LEASE_CONTRACT_VERSION
    assert renewed.revision_number == 3
    assert renewed.previous_lease_sha256 == active_second.semantic_sha256
    assert reacquired.contract_version == ACCOUNT_LEASE_CONTRACT_VERSION
    assert reacquired.fencing_generation == 2
    assert reacquired.revision_number == 1
    assert reacquired.previous_lease_sha256 is None

    with pytest.raises(
        RuntimeError,
        match="cannot downgrade after a v2 account lease revision has been persisted",
    ):
        command.downgrade(config, "0008_phase2_research")
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            EXPECTED_SCHEMA_REVISION
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase2_account_leases)
                .where(
                    phase2_account_leases.c.previous_lease_sha256 == active_second.semantic_sha256
                )
            )
            == 1
        )

    released.release(reacquired.fence)
    legacy_after_v2 = _legacy_account_lease(
        account_id=reacquired.account_id,
        owner_id="corrupt-legacy-worker",
        lease_id=canonical_id(
            "account-coordinator-lease",
            reacquired.account_id,
            3,
            "corrupt-legacy-worker",
            base + timedelta(seconds=21),
            policy.semantic_sha256,
        ),
        fencing_generation=3,
        revision_number=1,
        previous_lease_sha256=None,
        acquired_at=base + timedelta(seconds=21),
        heartbeat_at=base + timedelta(seconds=21),
        expires_at=base + timedelta(seconds=51),
        policy_sha256=policy.semantic_sha256,
    )
    corrupt_values = {
        **_legacy_lease_values(legacy_after_v2),
        "revision_number": 1,
        "previous_lease_sha256": None,
    }
    with engine.begin() as connection:
        connection.execute(sa.insert(phase2_account_leases), corrupt_values)
        connection.execute(
            sa.update(phase2_account_lease_heads)
            .where(phase2_account_lease_heads.c.account_id == legacy_after_v2.account_id)
            .values(
                last_fencing_generation=3,
                current_fencing_generation=3,
                current_lease_sha256=legacy_after_v2.semantic_sha256,
                updated_at=legacy_after_v2.heartbeat_at,
            )
        )
    with pytest.raises(
        AccountCoordinatorError,
        match="legacy account lease revision cannot follow a v2 revision",
    ):
        released.current()
    engine.dispose()


def test_0008_decision_first_equal_time_release_upgrades_without_reinterpretation(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase2-capacity-ordering-upgrade.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)

    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-QQQ", "US-ETF-SPY"),
    )
    first_target, first_batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("5")},
        target_id="legacy-same-time-parent",
    )
    second_target, second_batch = make_batch(
        portfolio,
        desired={"US-ETF-QQQ": Decimal("5")},
        target_id="legacy-same-time-observer",
    )
    capacity = snapshot(portfolio, available_cash=Decimal("700"))
    policy = AccountLeasePolicy(
        policy_id="phase2-sql-test-coordinator",
        policy_version="1.0.0",
        lease_ttl=timedelta(minutes=5),
        maximum_in_flight_duration=timedelta(seconds=5),
        takeover_safety_interval=timedelta(seconds=10),
    )
    legacy_lease = _legacy_account_lease(
        account_id=capacity.account_id,
        owner_id="legacy-ordering-worker",
        lease_id=canonical_id(
            "account-coordinator-lease",
            capacity.account_id,
            1,
            "legacy-ordering-worker",
            EVALUATED_AT,
            policy.semantic_sha256,
        ),
        fencing_generation=1,
        revision_number=1,
        previous_lease_sha256=None,
        acquired_at=EVALUATED_AT,
        heartbeat_at=EVALUATED_AT,
        expires_at=EVALUATED_AT + timedelta(minutes=5),
        policy_sha256=policy.semantic_sha256,
    )
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_leases),
            {
                **_legacy_lease_values(legacy_lease),
                "revision_number": 1,
                "previous_lease_sha256": None,
            },
        )
        connection.execute(
            sa.insert(phase2_account_lease_heads),
            {
                "account_id": capacity.account_id,
                "last_fencing_generation": 1,
                "current_fencing_generation": 1,
                "current_lease_sha256": legacy_lease.semantic_sha256,
                "updated_at": EVALUATED_AT,
            },
        )
    authority = SqlAccountCoordinatorAuthority(
        engine=engine,
        policy=policy,
        clock=MutableClock(EVALUATED_AT),
    )
    coordinator = SqlAccountCoordinator(
        account_id=capacity.account_id,
        authority=authority,
    )
    assert coordinator.current() == legacy_lease
    first_risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    first = first_risk.authorize(first_batch, first_target, legacy_lease.fence)
    assert first.reservation is not None
    release_at = first.expires_at
    second_risk = _repository(engine, capacity, coordinator, MutableClock(release_at))
    second = second_risk.authorize(second_batch, second_target, legacy_lease.fence)
    assert second.status is BatchRiskDecisionStatus.REJECTED
    lifecycle = SqlReservationLifecycleRepository(engine=engine, coordinator=coordinator)
    released = lifecycle.expire_unsent(
        reservation_id=first.reservation.reservation_id,
        authorization_id=first.authorizations[0].decision_id,
        fence=legacy_lease.fence,
        finality_reference="legacy-decision-first-same-time-release",
        observed_at=release_at,
        recorded_at=release_at,
    )
    assert second_risk.get_batch(second.decision_id) == second

    with engine.connect() as connection:
        rows = tuple(
            connection.execute(
                sa.select(phase2_batch_decisions).order_by(
                    phase2_batch_decisions.c.account_observation_sequence
                )
            ).mappings()
        )
        legacy_payloads: dict[str, str] = {}
        for row in rows:
            decision_id = str(row["decision_id"])
            decision = load_batch_risk_decision(connection, decision_id)
            assert decision is not None
            legacy_payloads[decision_id] = _decision_fact_payload(
                decision,
                _decode_active_capacity(row["active_capacity_payload"]),
                int(row["account_observation_sequence"]),
                capacity_observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
                fencing_generation=int(row["fencing_generation"]),
                lease_sha256=str(row["lease_sha256"]),
                fence_sha256=str(row["fence_sha256"]),
            )
    with engine.begin() as connection:
        for decision_id, canonical_payload in legacy_payloads.items():
            connection.execute(
                sa.update(phase2_batch_decisions)
                .where(phase2_batch_decisions.c.decision_id == decision_id)
                .values(
                    capacity_observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
                    canonical_payload=canonical_payload,
                )
            )
        connection.execute(
            sa.update(phase2_reservation_release_events).values(
                visible_after_observation_sequence=0,
                capacity_visibility_sha256=None,
            )
        )
    with engine.connect() as connection:
        assert load_batch_risk_decision(connection, second.decision_id) == second
        _verify_phase2_durability_integrity(connection)

    engine.dispose()
    command.downgrade(config, "0008_phase2_research")
    legacy_engine = create_engine(database_url)
    assert "capacity_observation_contract" not in {
        column["name"] for column in inspect(legacy_engine).get_columns("phase2_batch_decisions")
    }
    assert "visible_after_observation_sequence" not in {
        column["name"]
        for column in inspect(legacy_engine).get_columns("phase2_reservation_release_events")
    }
    legacy_engine.dispose()

    command.upgrade(config, "head")
    upgraded_engine = create_database_engine(database_url)
    upgraded_authority = SqlAccountCoordinatorAuthority(
        engine=upgraded_engine,
        policy=policy,
        clock=MutableClock(release_at),
    )
    upgraded_coordinator = SqlAccountCoordinator(
        account_id=capacity.account_id,
        authority=upgraded_authority,
    )
    upgraded_risk = _repository(
        upgraded_engine,
        capacity,
        upgraded_coordinator,
        MutableClock(release_at),
    )
    assert upgraded_risk.get_batch(second.decision_id) == second
    upgraded_lifecycle = SqlReservationLifecycleRepository(
        engine=upgraded_engine,
        coordinator=upgraded_coordinator,
    )
    assert upgraded_lifecycle.history(first.reservation.reservation_id) == (released.fact,)
    with upgraded_engine.connect() as connection:
        migrated_decisions = tuple(
            connection.scalars(sa.select(phase2_batch_decisions.c.capacity_observation_contract))
        )
        marker, visibility_sha256 = connection.execute(
            sa.select(
                phase2_reservation_release_events.c.visible_after_observation_sequence,
                phase2_reservation_release_events.c.capacity_visibility_sha256,
            )
        ).one()
        assert migrated_decisions == (
            LEGACY_CAPACITY_OBSERVATION_CONTRACT,
            LEGACY_CAPACITY_OBSERVATION_CONTRACT,
        )
        assert marker == 0
        assert visibility_sha256 is None
        _verify_phase2_durability_integrity(connection)
    upgraded_engine.dispose()


def test_phase2_durability_checks_reject_ambiguous_facts_and_allow_unit_postings() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    metadata.create_all(engine)
    instant = datetime(2026, 7, 20, 14, 30, tzinfo=UTC)

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                event_id="pending-not-first",
                attempt_id="attempt-not-required-for-check",
                sequence_number=2,
                state="pending",
                occurred_at=instant,
                recorded_at=instant,
                response_sha256=None,
                broker_order_id=None,
                error_class=None,
                canonical_payload="{}",
                semantic_sha256="a" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                event_id="in-flight-without-dispatch-receipt",
                attempt_id="attempt-not-required-for-check",
                sequence_number=2,
                state="in_flight",
                occurred_at=instant,
                recorded_at=instant,
                previous_event_sha256="a" * 64,
                canonical_payload="{}",
                semantic_sha256="b" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                event_id="abandoned-without-recovery-reason",
                attempt_id="attempt-not-required-for-check",
                sequence_number=2,
                state="abandoned",
                occurred_at=instant,
                recorded_at=instant,
                previous_event_sha256="a" * 64,
                canonical_payload="{}",
                semantic_sha256="c" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_order_events).values(
                event_id="accepted-with-execution-fields",
                order_id="order-not-required-for-check",
                broker_order_id="broker-order",
                broker_sequence=1,
                occurred_at=instant,
                received_at=instant,
                kind="accepted",
                reason=None,
                execution_id="unexpected-execution",
                execution_revision=1,
                supersedes_event_id=None,
                quantity=Decimal(1),
                price=Decimal(1),
                fee=Decimal(0),
                canonical_payload="{}",
                semantic_sha256="d" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_reservation_release_events).values(
                release_event_id="zero-release",
                reservation_id="reservation-not-required-for-check",
                authorization_id="authorization-not-required-for-check",
                order_id=None,
                attempt_id=None,
                order_event_id=None,
                reason="approval_expired_unsent",
                finality_reference="durably-never-dispatched",
                source_sha256="e" * 64,
                released_cash=Decimal(0),
                released_buy_exposure=Decimal(0),
                released_sell_quantity=Decimal(0),
                occurred_at=instant,
                recorded_at=instant,
                canonical_payload="{}",
                semantic_sha256="f" * 64,
            )
        )

    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_ledger_entries).values(
                entry_id="split-entry",
                account_id="simulation-account",
                kind="stock_split",
                reference_id="split-reference",
                source_sha256="e" * 64,
                effective_at=instant,
                recorded_at=instant,
                canonical_payload="{}",
                semantic_sha256="f" * 64,
            )
        )
        connection.execute(
            sa.insert(phase2_ledger_postings).values(
                entry_id="split-entry",
                line_number=1,
                account="security_units:instrument-a",
                currency="USD",
                debit=Decimal(0),
                credit=Decimal(0),
                units_delta=Decimal(5),
                instrument_id="instrument-a",
                semantic_sha256="1" * 64,
            )
        )

    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_ledger_postings)) == 1
        )


def test_phase_zero_database_upgrades_to_point_in_time_catalog(tmp_path: Path) -> None:
    database_path = tmp_path / "upgrade.sqlite"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database_path}")

    command.upgrade(config, "0003_submission_attempts")
    engine = create_engine(f"sqlite+pysqlite:///{database_path}")
    assert "dataset_manifests" not in inspect(engine).get_table_names()

    command.upgrade(config, "0004_point_in_time_data")

    assert "dataset_manifests" in inspect(engine).get_table_names()
    assert "market_data_admission_runs" not in inspect(engine).get_table_names()

    command.upgrade(config, "0005_market_data_admission")

    assert "market_data_admission_runs" in inspect(engine).get_table_names()
    assert "replay_run_manifests" not in inspect(engine).get_table_names()
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO data_objects "
                "(object_id, object_key, byte_checksum, semantic_checksum, format, size_bytes, "
                "created_at) VALUES (:object_id, :object_key, :byte_checksum, "
                ":semantic_checksum, 'parquet', 1, :created_at)"
            ),
            {
                "object_id": "a" * 64,
                "object_key": f"normalized/sha256/aa/{'a' * 64}.parquet",
                "byte_checksum": "a" * 64,
                "semantic_checksum": "b" * 64,
                "created_at": "2026-07-18T00:00:00+00:00",
            },
        )
        connection.execute(
            text(
                "INSERT INTO dataset_partitions "
                "(partition_id, object_id, job_id, source_id, layer, status, schema_version, "
                "price_basis, row_count, event_time_start, event_time_end, available_at_start, "
                "available_at_end, semantic_checksum, created_at) VALUES "
                "(:partition_id, :object_id, :job_id, :source_id, 'normalized', 'published', "
                "'raw-bar-v1', 'raw', 1, :instant, :instant, :instant, :instant, "
                ":semantic_checksum, :instant)"
            ),
            {
                "partition_id": "c" * 64,
                "object_id": "a" * 64,
                "job_id": "d" * 64,
                "source_id": "legacy-fixture",
                "semantic_checksum": "b" * 64,
                "instant": "2026-07-18T00:00:00+00:00",
            },
        )
        connection.execute(
            text(
                "INSERT INTO calendar_versions "
                "(calendar_version, name, timezone, tzdata_version, content_hash, created_at) "
                "VALUES ('legacy-calendar', 'Legacy', 'UTC', '2026a', :hash, :created_at)"
            ),
            {"hash": "e" * 64, "created_at": "2026-07-18T00:00:00+00:00"},
        )
        connection.execute(
            text(
                "INSERT INTO universe_versions "
                "(universe_version, name, effective_as_of, created_at, content_hash) "
                "VALUES ('legacy-universe', 'Legacy', :created_at, :created_at, :hash)"
            ),
            {"hash": "f" * 64, "created_at": "2026-07-18T00:00:00+00:00"},
        )
        connection.execute(
            text(
                "INSERT INTO corporate_action_sets "
                "(corporate_action_version, name, content_hash, created_at) "
                "VALUES ('legacy-actions', 'Legacy', :hash, :created_at)"
            ),
            {"hash": "0" * 64, "created_at": "2026-07-18T00:00:00+00:00"},
        )

    command.upgrade(config, "head")

    assert "replay_run_manifests" in inspect(engine).get_table_names()
    assert "phase2_batch_members" in inspect(engine).get_table_names()
    assert "phase2_batch_reservations" in inspect(engine).get_table_names()
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            EXPECTED_SCHEMA_REVISION
        )
        assert (
            connection.scalar(text("SELECT semantic_checksum_version FROM data_objects"))
            == "input-v1"
        )
        assert (
            connection.scalar(text("SELECT semantic_checksum_version FROM dataset_partitions"))
            == "input-v1"
        )
        for table_name in (
            "calendar_versions",
            "universe_versions",
            "corporate_action_sets",
        ):
            assert (
                connection.scalar(text(f"SELECT content_hash_version FROM {table_name}"))
                == "input-v1"
            )
