"""An empty W4 schema is not an initialized selected-account readiness proof.

The original pre-C1 constructors are real, but no initialization/capture/control/
venue publication is performed. This is a fresh modeled fixture, not a cold
loader, existing account, process, HTTP, clock-source or execution qualification.
"""

import os
import threading
from contextlib import ExitStack, contextmanager
from datetime import UTC, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from apps.trader import continuous_readiness_owner as owner_module
from apps.trader.synthetic_session_genesis import (
    _assemble_synthetic_owners,
    _synthetic_genesis_values,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.adapters.runtime_clock_evidence import RuntimeClockSampler
from packages.application import personal_codec
from packages.application.personal_runtime import LocalInstanceGuard
from packages.application.reference_strategy import ReferenceStrategy
from packages.application.synthetic_continuous_inputs import synthetic_continuous_inputs
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.account_coordinator import AccountLeasePolicy
from packages.domain.clock import SimulatedClock
from packages.domain.continuous_runtime_source_contracts import (
    RUNTIME_SOURCE_SCHEMA,
    ContinuousRuntimeSourceDescriptor,
    runtime_producer_map,
)
from packages.domain.daily_runtime_contracts import RuntimeProducerSpec
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.runtime_operating_contracts import CLOCK_SCHEMA, RuntimeClockObservation
from packages.domain.stateful_venue_contracts import VenueSourceReference
from packages.domain.walking_thread import WalkingThread
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.applied_reconciliation_schema import APPLIED_RECONCILIATION_TABLES
from packages.persistence.continuous_account_schema import CONTINUOUS_ACCOUNT_TABLES
from packages.persistence.continuous_forward_sources import SqlContinuousForwardSources
from packages.persistence.continuous_integrity import SqlContinuousIntegrityReader
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.database import (
    EXPECTED_SCHEMA_REVISION,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.risk import SqlRiskDecisionRepository
from packages.persistence.runtime_operating_evidence import SqlRuntimeOperatingEvidence
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)
from packages.persistence.stateful_venue import SqlStatefulVenue
from packages.persistence.walking_thread import WalkingThreadUnitOfWork
from tests.integration.test_continuous_synthetic_full_readiness import (
    _all_rows,
    _assert_scopes_closed,
)
from tests.integration.test_continuous_synthetic_offline_configuration import _exclusive_file
from tests.integration.test_continuous_synthetic_session_genesis import PINS

ROOT = Path(__file__).resolve().parents[2]
W4_TABLES = (
    *JOURNAL_TABLES,
    *APPLIED_RECONCILIATION_TABLES,
    *DAILY_RUNTIME_TABLES,
    *CONTINUOUS_ACCOUNT_TABLES,
)
CONTROL_TABLES = (
    phase5_operational_control_transitions,
    phase5_operational_control_heads,
    phase5_operational_control_completions,
)


def _counts(engine, tables):
    with engine.connect() as connection:
        return tuple(
            connection.scalar(sa.select(sa.func.count()).select_from(table)) for table in tables
        )


def _facts(account, venue, roots):
    # These are the actual fresh application rows/revision and private object
    # bytes, not a claim about physical SQLite/internal storage representation.
    return (
        _all_rows(account),
        _all_rows(venue),
        tuple(
            tuple(sorted((path.name, path.read_bytes()) for path in root.iterdir()))
            for root in roots
        ),
    )


def _without_lease_lifecycle(facts):
    account, venue, objects = facts
    names = {
        phase2_account_leases.name,
        phase2_account_lease_heads.name,
        phase2_account_lease_releases.name,
    }
    return tuple((name, rows) for name, rows in account if name not in names), venue, objects


def test_empty_original_sql_graph_cannot_become_selected_account_ready(tmp_path):
    tmp_path.chmod(0o700)
    caller = threading.current_thread()
    observed = SimpleNamespace(
        thread=None,
        events=[],
        release_attempts=0,
        schema_passed=False,
        constructor_denial=None,
        constructor_accepted=False,
        builder_exited=False,
    )
    root = tmp_path / "pre-c1-readiness"
    lock_path = root / "instance.lock"

    @contextmanager
    def held_guard():
        guard = LocalInstanceGuard(lock_path)
        guard.__enter__()
        primary = None
        try:
            yield guard
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                if primary is None:
                    guard.__exit__(None, None, None)
                else:
                    guard.__exit__(type(primary), primary, primary.__traceback__)
            except BaseException as cleanup_error:
                if primary is not None:
                    raise BaseExceptionGroup(
                        "pre-C1 setup and guard cleanup failed", [primary, cleanup_error]
                    ) from None
                raise
            observed.events.append(("guard-exit", threading.current_thread()))

    @contextmanager
    def owned_engine(engine, name):
        primary = None
        try:
            yield engine
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                engine.dispose()
            except BaseException as cleanup_error:
                if primary is not None:
                    raise BaseExceptionGroup(
                        "pre-C1 setup and engine cleanup failed", [primary, cleanup_error]
                    ) from None
                raise
            # This event records successful return, never merely an attempt.
            observed.events.append((name, threading.current_thread()))

    @contextmanager
    def open_runtime(stop_event):
        observed.thread = threading.current_thread()
        assert observed.thread is not caller
        observed.events.append(("construct", observed.thread))
        root.mkdir(mode=0o700)
        try:
            with held_guard() as guard:
                observed.events.append(("guard-enter", threading.current_thread()))
                held = os.fstat(guard.fileno())
                observed.lock_identity = held.st_dev, held.st_ino
                with ExitStack() as cleanup:
                    account_path, venue_path = root / "account.sqlite", root / "venue.sqlite"
                    _exclusive_file(account_path)
                    _exclusive_file(venue_path)
                    url = f"sqlite+pysqlite:///{account_path}"
                    migration = Config()
                    migration.set_main_option("script_location", str(ROOT / "migrations"))
                    migration.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
                    migration.attributes["aqt_explicit_database_url"] = url
                    command.upgrade(migration, EXPECTED_SCHEMA_REVISION)

                    account = create_database_engine(url)
                    cleanup.enter_context(owned_engine(account, "dispose-account"))
                    venue = create_database_engine(f"sqlite+pysqlite:///{venue_path}")
                    cleanup.enter_context(owned_engine(venue, "dispose-venue"))
                    metadata.create_all(venue, tables=JOURNAL_TABLES)
                    with account.connect() as connection:
                        assert tuple(
                            connection.scalars(sa.text("SELECT version_num FROM alembic_version"))
                        ) == (EXPECTED_SCHEMA_REVISION,)
                    artifacts = LocalResearchArtifactStore(root / "account-objects")
                    venue_artifacts = LocalResearchArtifactStore(root / "venue-objects")
                    roots = artifacts._root, venue_artifacts._root
                    synthetic = synthetic_continuous_inputs(
                        fixture="regime", pins=PINS, session_count=4, warmup_count=1
                    )
                    spec = synthetic.inputs.spec
                    venue_pin = VersionPin(
                        "synthetic-venue", "pre-c1-model-1", content_digest("venue")
                    )
                    producer = VersionPin(
                        "synthetic-capture", "pre-c1-model-1", content_digest("capture")
                    )
                    seed, model, scope = _synthetic_genesis_values(spec, venue_pin)
                    assert seed.amount == Decimal("10000")
                    assert model.live_authorized is False
                    clock = SimulatedClock(spec.initialized_at)
                    policy = AccountLeasePolicy(
                        "synthetic-session-account-lease/1",
                        "1",
                        timedelta(seconds=60),
                        timedelta(seconds=5),
                        timedelta(seconds=10),
                    )
                    coordinator = SqlAccountCoordinator(
                        account_id=scope.account_id,
                        authority=SqlAccountCoordinatorAuthority(
                            engine=account, clock=clock, policy=policy
                        ),
                    )
                    lease = coordinator.acquire("synthetic-pre-c1-owner")
                    primary = None
                    try:
                        assert lease.fencing_generation == lease.revision_number == 1
                        assert lease.previous_lease_sha256 is None
                        assert lease.heartbeat_at == lease.acquired_at
                        assert lease.expires_at - lease.acquired_at == timedelta(seconds=60)
                        assert lease.policy_sha256 == policy.semantic_sha256
                        accounting = PersonalAccounting()
                        forward = SqlContinuousForwardSources(
                            account,
                            artifacts=artifacts,
                            codec=personal_codec,
                            evidence_class="synthetic_fixture",
                        )
                        operating = SqlRuntimeOperatingEvidence(
                            account,
                            artifacts=artifacts,
                            codec=personal_codec,
                            clock_sampler=RuntimeClockSampler.simulation_model(
                                scope=scope,
                                utc_now=clock.now,
                                monotonic_now_ns=lambda: 1_000_000_000,
                                epoch_provider=lambda: "synthetic-pre-c1-model",
                            ),
                            journal=SqlDurableJournal(
                                account,
                                codec=personal_codec,
                                record_types={CLOCK_SCHEMA: RuntimeClockObservation},
                            ),
                        )
                        model_ref = artifacts.put(personal_codec.encode_record(model))
                        runtime = SqlContinuousRuntimeSources(
                            account,
                            coordinator=coordinator,
                            journal=SqlDurableJournal(
                                account,
                                codec=personal_codec,
                                record_types={
                                    RUNTIME_SOURCE_SCHEMA: ContinuousRuntimeSourceDescriptor
                                },
                            ),
                            artifacts=artifacts,
                            codec=personal_codec,
                            forward_sources=forward,
                            operating=operating,
                            accounting=accounting,
                            strategy=ReferenceStrategy(
                                reserve_fraction=spec.risk_policy.adverse_reserve_fraction,
                                fee_per_share=spec.risk_policy.fee_per_share,
                            ),
                            venue_model=model,
                            venue_reference=VenueSourceReference(
                                model.producer, model.semantic_sha256, model_ref
                            ),
                            producer_map=runtime_producer_map(
                                account_id=scope.account_id,
                                venue_model=model,
                                daily=RuntimeProducerSpec(
                                    role="daily_inputs",
                                    producer=producer,
                                    provider_id="fixture",
                                    source_environment="synthetic",
                                    account_scope=scope.account_id,
                                ),
                                quotes=RuntimeProducerSpec(
                                    role="quotes",
                                    producer=producer,
                                    provider_id="etrade",
                                    source_environment="production",
                                    account_scope=scope.account_id,
                                ),
                            ),
                            benchmark_instrument_id=next(
                                instrument
                                for instrument, symbol in spec.instruments
                                if symbol == "SPY"
                            ),
                            current_fence=lambda: lease.fence,
                        )
                        owners = _assemble_synthetic_owners(
                            runtime, scope=scope, fence=lease.fence, owner_id=lease.owner_id
                        )
                        venue_owner = SqlStatefulVenue(
                            venue,
                            model=model,
                            artifacts=venue_artifacts,
                            codec=personal_codec,
                            accounting=accounting,
                        )
                        reader = SqlContinuousIntegrityReader(
                            account,
                            scope=scope,
                            reconciliation_scope=owners.venue_sources.scope,
                            account=owners.account,
                            daily=owners.daily,
                            publisher=owners.runtime.publisher,
                            associations=SqlRuntimeOwnerAssociations(
                                owner_dependencies=owners.owners
                            ),
                            journals=(
                                owners.account.journal,
                                owners.runtime.publisher.journal,
                                owners.venue_sources.journal,
                                owners.runtime.journal,
                                owners.runtime.forward_sources.journal,
                                owners.runtime.operating.journal,
                                owners.owners.commands.journal,
                            ),
                            fence=lease.fence,
                        )
                        assert owners.account.restore(scope) is None
                        assert len(W4_TABLES) == 16
                        assert _counts(account, W4_TABLES) == (0,) * 16
                        assert _counts(account, CONTROL_TABLES) == (0, 0, 0)
                        assert _counts(venue, JOURNAL_TABLES) == (0, 0, 0)
                        assert owners.owners.commands.authenticator.security._enabled is False
                        # Only the separate original fixed-tape prerequisite is
                        # published; this is not continuous account funding.
                        result = WalkingThread.run(
                            SqlRiskDecisionRepository(account, WalkingThread.risk_authority())
                        )
                        WalkingThreadUnitOfWork(account).persist(result)
                        assert result.risk_account_snapshot.account_id != scope.account_id
                        assert result.account.cash == Decimal("98989.00")
                        assert result.account.equity == Decimal("99999.00")
                        assert artifacts.read(model_ref) == personal_codec.encode_record(model)
                        assert tuple(path.name for path in artifacts._root.iterdir()) == (
                            model_ref.object_sha256 + ".json",
                        )
                        assert tuple(venue_artifacts._root.iterdir()) == ()
                        before = _facts(account, venue, roots)
                        # No reader and no False flag: the unchanged full
                        # verifier legitimately skips continuous proof when all
                        # sixteen W4 tables are empty, despite a current lease.
                        assert (
                            verify_operational_schema(account, research_codec=personal_codec)
                            is None
                        )
                        observed.schema_passed = True
                        assert _facts(account, venue, roots) == before
                        assert _counts(account, W4_TABLES) == (0,) * 16
                        try:
                            selected = owner_module._ReadinessRuntime(
                                reader=reader,
                                lease=lease,
                                guard=guard,
                                venue=venue_owner,
                                venue_engine=venue,
                                stop_event=stop_event,
                            )
                        except ValueError as error:
                            observed.constructor_denial = error.args
                            _assert_scopes_closed(reader)
                            assert _facts(account, venue, roots) == before
                            observed.events.append(("runtime-denied", threading.current_thread()))
                            raise
                        observed.constructor_accepted = True
                        yield selected
                    except BaseException as error:
                        primary = error
                        raise
                    finally:
                        observed.release_attempts += 1
                        observed.events.append(("release", threading.current_thread()))
                        try:
                            before_release = _facts(account, venue, roots)
                            release = coordinator.release(lease.fence)
                            assert release.fence == lease.fence
                            assert release.lease_sha256 == lease.semantic_sha256
                            assert release.policy_sha256 == policy.semantic_sha256
                            assert release.released_at == clock.now()
                            assert coordinator.current() is None
                            with account.connect() as connection:
                                leases = (
                                    connection.execute(sa.select(phase2_account_leases))
                                    .mappings()
                                    .all()
                                )
                                releases = (
                                    connection.execute(sa.select(phase2_account_lease_releases))
                                    .mappings()
                                    .all()
                                )
                                head = (
                                    connection.execute(sa.select(phase2_account_lease_heads))
                                    .mappings()
                                    .one()
                                )
                            assert len(leases) == len(releases) == 1
                            assert leases[0]["lease_sha256"] == lease.semantic_sha256
                            assert releases[0]["release_sha256"] == release.semantic_sha256
                            assert releases[0]["lease_sha256"] == lease.semantic_sha256
                            assert releases[0]["owner_id"] == lease.owner_id
                            assert releases[0]["lease_id"] == lease.lease_id
                            assert releases[0]["policy_sha256"] == lease.policy_sha256
                            assert head["account_id"] == lease.account_id
                            assert head["last_fencing_generation"] == 1
                            assert head["current_fencing_generation"] is None
                            assert head["current_lease_sha256"] is None
                            assert head["updated_at"].replace(tzinfo=UTC) == clock.now()
                            after_release = _facts(account, venue, roots)
                            assert (
                                dict(after_release[0])[phase2_account_leases.name]
                                == dict(before_release[0])[phase2_account_leases.name]
                            )
                            assert _without_lease_lifecycle(
                                after_release
                            ) == _without_lease_lifecycle(before_release)
                            assert _counts(account, W4_TABLES) == (0,) * 16
                            assert _counts(account, CONTROL_TABLES) == (0, 0, 0)
                            assert _counts(venue, JOURNAL_TABLES) == (0, 0, 0)
                            assert coordinator._state.observations is None
                            observed.released = True
                        except BaseException as cleanup_error:
                            if primary is not None:
                                raise BaseExceptionGroup(
                                    "pre-C1 setup and cleanup failed", [primary, cleanup_error]
                                ) from None
                            raise
        finally:
            # Generator exit is distinct from successful individual cleanup;
            # failures above keep their ordered original-plus-cleanup groups.
            observed.builder_exited = True

    owner = owner_module.ContinuousReadinessOwner(_open_runtime=open_runtime)
    try:
        status = owner.start()
        assert status.phase in ("stopping", "stopped")
        assert observed.thread is not None
        observed.thread.join(8)
        assert not observed.thread.is_alive()
        terminal = owner.status()
        assert terminal.phase == "stopped" and terminal.cleanup_complete
        assert terminal.primary_failure == "startup_failed"
        assert terminal.cleanup_failure is None
        assert observed.schema_passed and not observed.constructor_accepted
        assert observed.constructor_denial == ("READINESS_NONEMPTY_ACCOUNT_REQUIRED",)
        assert owner.check("empty-is-not-ready").status == "unavailable"
        assert observed.release_attempts == 1 and observed.released
        assert observed.builder_exited
        names = [name for name, _thread in observed.events]
        assert names == [
            "construct",
            "guard-enter",
            "runtime-denied",
            "release",
            "dispose-venue",
            "dispose-account",
            "guard-exit",
        ]
        assert all(thread is observed.thread for _name, thread in observed.events)
        with LocalInstanceGuard(lock_path) as guard:
            current = os.fstat(guard.fileno())
            assert (current.st_dev, current.st_ino) == observed.lock_identity
    finally:
        owner.stop()
        if observed.thread is not None:
            observed.thread.join(8)
            assert not observed.thread.is_alive()
