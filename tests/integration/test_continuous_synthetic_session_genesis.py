"""Fresh public capture/genesis joins; no fixture owner or authorization shortcut."""

from contextlib import ExitStack
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest
import sqlalchemy as sa

from apps.trader.synthetic_session_capture import capture_synthetic_bootstrap
from apps.trader.synthetic_session_genesis import initialize_synthetic_session
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.application.synthetic_continuous_inputs import synthetic_continuous_inputs
from packages.domain.account_coordinator import AccountCoordinatorError, AccountLeasePolicy
from packages.domain.clock import SimulatedClock
from packages.domain.forward_capture_contracts import CAPTURE_SCHEMA, ForwardCaptureRecord
from packages.domain.operational_control import OperationalControlState
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.persistence.continuous_account import ContinuousAccountConflict
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase5_operational_control_transitions,
)

PINS = tuple(
    VersionPin(name, "synthetic-genesis-integration-model/1", content_digest((name, "model")))
    for name in sorted(
        (
            "engine",
            "source",
            "dependency_lock",
            "tzdata",
            "availability",
            "actions",
            "numeric",
            "benchmark",
            "report",
            "dirty_patch",
        )
    )
)


@pytest.fixture
def captured(tmp_path):
    # These are ordinary fresh stores owned and disposed by this test, not a
    # retained fixture or shared test Harness. Build pins identify modeled inputs.
    with ExitStack() as cleanup:
        account = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'account.sqlite'}")
        cleanup.callback(account.dispose)
        venue = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'venue.sqlite'}")
        cleanup.callback(venue.dispose)
        metadata.create_all(account)
        metadata.create_all(venue, tables=JOURNAL_TABLES)
        artifacts = LocalResearchArtifactStore(tmp_path / "account-objects")
        venue_artifacts = LocalResearchArtifactStore(tmp_path / "venue-objects")
        synthetic = synthetic_continuous_inputs(fixture="regime", pins=PINS)
        producer = VersionPin("synthetic-capture", "integration-model/1", content_digest("capture"))
        journal = SqlDurableJournal(
            account, codec=codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
        )
        bootstrap = capture_synthetic_bootstrap(
            synthetic,
            calendar_pin=VersionPin(
                "synthetic-calendar",
                "integration-model/1",
                content_digest(synthetic.inputs.spec.calendar),
            ),
            producer_pin=producer,
            journal=journal,
            publisher=SqlForwardCapturePublication(account, journal=journal),
            artifacts=artifacts,
            codec=codec,
        )
        yield (
            bootstrap,
            {
                "account_engine": account,
                "venue_engine": venue,
                "account_artifacts": artifacts,
                "venue_artifacts": venue_artifacts,
                "clock": SimulatedClock(bootstrap.inputs.spec.initialized_at),
                "monotonic_now_ns": lambda: 1_000_000_000,
                "epoch_id": "synthetic-genesis-test-model-1",
                "owner_id": "synthetic-startup",
                "venue_pin": VersionPin(
                    "synthetic-venue", "integration-model/1", content_digest("venue")
                ),
                "quote_producer": producer,
            },
        )


def _counts(engine, tables):
    with engine.connect() as connection:
        return tuple(
            connection.scalar(sa.select(sa.func.count()).select_from(table)) for table in tables
        )


def _rows(engine, tables):
    with engine.connect() as connection:
        return tuple(
            tuple(connection.execute(sa.select(table).order_by(*table.primary_key.columns)))
            for table in tables
        )


def _released(engine):
    with engine.connect() as connection:
        row = connection.execute(sa.select(phase2_account_lease_heads)).mappings().one()
    assert row["last_fencing_generation"] == 1
    assert row["current_fencing_generation"] is None
    assert row["current_lease_sha256"] is None
    assert _counts(engine, (phase2_account_leases, phase2_account_lease_releases)) == (1, 1)


def test_synthetic_genesis_authenticates_c1_with_empty_b_and_halted_control(captured):
    bootstrap, ports = captured
    result = initialize_synthetic_session(bootstrap, **ports)
    receipt = result.restored.receipt
    checkpoint = result.restored.checkpoint
    assert receipt.commit.sequence == 1
    assert checkpoint.inputs == bootstrap.inputs
    assert result.restored.request == bootstrap.inputs
    assert checkpoint.inputs.spec.live_authorized is False
    assert checkpoint.inputs.spec.risk_policy == bootstrap.inputs.spec.risk_policy
    assert checkpoint.inputs.spec.execution_policy == bootstrap.inputs.spec.execution_policy
    assert len(checkpoint.state.cash_flows) == 1
    assert checkpoint.state.cash_flows[0].amount == Decimal("10000")
    assert not checkpoint.state.submissions
    assert not checkpoint.state.broker_events
    assert not checkpoint.state.commitments
    assert not checkpoint.runtime_decisions
    assert result.inventory.assignment is None
    assert not result.inventory.assignment_rows
    assert not result.inventory.admissions
    assert not result.inventory.obligations.bindings
    assert not result.inventory.attempts
    assert not result.inventory.observed_groups
    assert result.inventory.control == result.control
    assert result.control.effective_state is OperationalControlState.HALTED
    assert result.control.sequence_number == 1
    assert result.control.active_operation is None
    assert _counts(ports["account_engine"], DAILY_RUNTIME_TABLES) == (0,) * len(
        DAILY_RUNTIME_TABLES
    )
    assert _counts(
        ports["account_engine"],
        (continuous_account_commits, phase5_operational_control_transitions),
    ) == (1, 1)
    assert result.account.coordinator is result.daily.coordinator
    assert result.runtime_sources.accounts is result.account
    assert result.runtime_sources.daily is result.daily
    assert result.owners.accounts is result.account
    result.account.require_resolved(result.restored)
    result.daily.require_resolved_snapshot(result.inventory)
    retained_tables = (continuous_account_commits, journal_entries, phase2_account_lease_heads)
    retained_before = _rows(ports["account_engine"], retained_tables)
    # The initializer authenticated this original receipt before releasing its
    # fence. Old owners cannot acquire authority from that retained result.
    # Reconstructing owners under a fresh explicit lease is a separate check.
    with pytest.raises(ContinuousAccountConflict, match=r"^CONTINUOUS_RETAINED_INDEX_INVALID$"):
        result.account.restore(result.scope)
    assert _rows(ports["account_engine"], retained_tables) == retained_before
    _released(ports["account_engine"])
    assert result.release.fence == result.lease.fence
    assert result.release.lease_sha256 == result.lease.semantic_sha256
    assert result.account.coordinator.current() is None
    with pytest.raises(AccountCoordinatorError):
        result.account.coordinator.revalidate(result.lease.fence)


def test_synthetic_venue_is_independent_seeded_without_commands_or_send_authority(captured):
    bootstrap, ports = captured
    result = initialize_synthetic_session(bootstrap, **ports)
    observed = result.venue.read()
    assert observed.head.sequence == 1 and observed.state.sequence == 0
    assert not observed.state.commands
    assert not observed.state.acknowledgments
    assert not observed.state.accounting.submissions
    assert not observed.state.accounting.commitments
    assert observed.state.accounting.cash_flows == result.restored.checkpoint.state.cash_flows
    assert result.venue.model.live_authorized is False
    assert result.venue.model.source_mode == "synthetic_fixture"
    assert all(
        source.provider == "fixture" and source.environment == "synthetic"
        for source in result.venue.model.sources
    )
    assert result.venue.verified_sources is None
    assert _counts(ports["venue_engine"], JOURNAL_TABLES) == (1, 1, 1)
    assert result.lease.expires_at - result.lease.acquired_at == timedelta(seconds=60)
    assert (
        result.lease.policy_sha256
        == AccountLeasePolicy(
            "synthetic-session-account-lease/1",
            "1",
            timedelta(seconds=60),
            timedelta(seconds=5),
            timedelta(seconds=10),
        ).semantic_sha256
    )
    _released(ports["account_engine"])


def test_synthetic_genesis_rejects_second_use_without_adopting_or_erasing(captured):
    bootstrap, ports = captured
    result = initialize_synthetic_session(bootstrap, **ports)
    tables = (
        continuous_account_commits,
        phase2_account_leases,
        phase2_account_lease_releases,
        journal_entries,
    )
    before = _counts(ports["account_engine"], tables)
    venue_before = result.venue.read()
    objects = tuple(sorted(path.name for path in ports["account_artifacts"]._root.iterdir()))
    with pytest.raises(ValueError, match="fresh"):
        initialize_synthetic_session(bootstrap, **ports)
    assert _counts(ports["account_engine"], tables) == before
    assert result.venue.read() == venue_before
    assert (
        tuple(sorted(path.name for path in ports["account_artifacts"]._root.iterdir())) == objects
    )
    _released(ports["account_engine"])


@pytest.mark.parametrize("change", ["slippage", "risk", "cash", "source"])
def test_synthetic_genesis_rejects_nondefault_profile_before_initialization(captured, change):
    bootstrap, ports = captured
    spec = bootstrap.inputs.spec
    if change == "slippage":
        spec = replace(
            spec, execution_policy=replace(spec.execution_policy, slippage_bps=Decimal("0"))
        )
    elif change == "risk":
        spec = replace(spec, risk_policy=replace(spec.risk_policy, max_open_intents=3))
    elif change == "cash":
        spec = replace(spec, initial_cash=Decimal("20000"))
    else:
        spec = replace(spec, source_mode="recorded_as_observed")
    changed = replace(bootstrap, inputs=replace(bootstrap.inputs, spec=spec))
    with pytest.raises(ValueError, match="default profile"):
        initialize_synthetic_session(changed, **ports)
    assert _counts(
        ports["account_engine"],
        (continuous_account_commits, phase2_account_leases, phase5_operational_control_transitions),
    ) == (0, 0, 0)
    assert _counts(ports["venue_engine"], JOURNAL_TABLES) == (0, 0, 0)


def test_synthetic_genesis_rejects_missing_original_capture_bytes_without_new_facts(captured):
    bootstrap, ports = captured
    reference = bootstrap.closure.publications[0].record.raw_object
    path = ports["account_artifacts"]._root / (reference.object_sha256 + ".json")
    original = path.read_bytes()
    # Negative input damage; no owner or registry is fabricated and no check is replaced.
    path.write_bytes(b"x" * len(original))
    with pytest.raises(ValueError, match=r"^CAPTURE_SOURCE_RESOLUTION_FAILED$"):
        initialize_synthetic_session(bootstrap, **ports)
    assert path.read_bytes() == b"x" * len(original)
    assert _counts(
        ports["account_engine"],
        (continuous_account_commits, phase2_account_leases, phase5_operational_control_transitions),
    ) == (0, 0, 0)
    assert _counts(ports["venue_engine"], JOURNAL_TABLES) == (0, 0, 0)


def test_synthetic_genesis_requires_separate_actual_databases(captured):
    bootstrap, ports = captured
    with pytest.raises(ValueError, match="independent databases"):
        initialize_synthetic_session(
            bootstrap, **{**ports, "venue_engine": ports["account_engine"]}
        )
    assert _counts(
        ports["account_engine"], (continuous_account_commits, phase2_account_leases)
    ) == (0, 0)


@pytest.mark.parametrize("extra", ["temporary_shadow", "attached"])
def test_synthetic_genesis_rejects_additional_sqlite_objects_before_writes(captured, extra):
    bootstrap, ports = captured
    engine = ports["account_engine"]
    with engine.connect() as connection:
        if extra == "temporary_shadow":
            connection.exec_driver_sql(
                "CREATE TEMP TABLE personal_continuous_account_commits (hidden TEXT)"
            )
        else:
            connection.exec_driver_sql("ATTACH DATABASE ':memory:' AS additional")
        connection.commit()
    try:
        with pytest.raises(ValueError, match="one explicit file database"):
            initialize_synthetic_session(bootstrap, **ports)
        assert _counts(engine, (phase2_account_leases, phase5_operational_control_transitions)) == (
            0,
            0,
        )
        assert _counts(ports["venue_engine"], JOURNAL_TABLES) == (0, 0, 0)
    finally:
        with engine.connect() as connection:
            if extra == "temporary_shadow":
                connection.exec_driver_sql("DROP TABLE temp.personal_continuous_account_commits")
            else:
                connection.exec_driver_sql("DETACH DATABASE additional")
            connection.commit()
    assert _counts(engine, (continuous_account_commits,)) == (0,)


def test_synthetic_genesis_c_failure_retains_partial_facts_and_releases_original_fence(captured):
    bootstrap, ports = captured
    engine = ports["account_engine"]
    failure = RuntimeError("injected physical C insert failure")
    calls = []

    def fail_c_insert(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("INSERT INTO PERSONAL_CONTINUOUS_ACCOUNT_COMMITS"):
            calls.append(statement)
            raise failure

    sa.event.listen(engine, "before_cursor_execute", fail_c_insert)
    try:
        with pytest.raises(RuntimeError) as caught:
            initialize_synthetic_session(bootstrap, **ports)
        assert caught.value is failure
    finally:
        sa.event.remove(engine, "before_cursor_execute", fail_c_insert)
    assert len(calls) == 1
    assert _counts(engine, (continuous_account_commits,)) == (0,)
    assert _counts(engine, DAILY_RUNTIME_TABLES) == (0,) * len(DAILY_RUNTIME_TABLES)
    assert _counts(ports["venue_engine"], JOURNAL_TABLES) == (1, 1, 1)
    control = SqlOperationalControlRepository(engine=engine, clock=ports["clock"]).load(
        bootstrap.inputs.spec.account_id
    )
    assert control is not None and control.effective_state is OperationalControlState.HALTED
    _released(engine)
    before = _counts(
        engine, (journal_entries, phase2_account_leases, phase2_account_lease_releases)
    )
    with pytest.raises(ValueError, match="fresh"):
        initialize_synthetic_session(bootstrap, **ports)
    assert (
        _counts(engine, (journal_entries, phase2_account_leases, phase2_account_lease_releases))
        == before
    )
    assert _counts(ports["venue_engine"], JOURNAL_TABLES) == (1, 1, 1)
