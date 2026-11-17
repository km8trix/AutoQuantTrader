"""Initialize one fresh synthetic account and independent venue, HALTED.

The caller owns the already-created temporary stores and modeled clock. This
join authenticates retained synthetic captures, publishes only genesis, and
releases its original fence before returning. It does not authenticate an owner,
install an assignment, rearm controls, start a session, or adopt partial state.
Failures retain every committed fact and immutable object for inspection.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import sqlalchemy as sa

from apps.api.backtest_views import LocalOperatorSecurity
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from apps.trader.synthetic_session_capture import SyntheticBootstrapCapture
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.adapters.runtime_clock_evidence import RuntimeClockSampler
from packages.application import personal_codec as codec
from packages.application.continuous_account_transition import ContinuousAccountTransitionPreparer
from packages.application.continuous_reconciliation import (
    ContinuousReconciliationTransitionResolver,
)
from packages.application.continuous_source_events import compile_continuous_bootstrap
from packages.application.personal_inputs import SYNTHETIC_CALENDAR
from packages.application.reference_strategy import ReferenceStrategy
from packages.application.venue_reconciliation import VenueReconciliationResolver
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.account_coordinator import (
    AccountFence,
    AccountLease,
    AccountLeasePolicy,
    AccountLeaseRelease,
)
from packages.domain.accounting_contracts import ExecutionPolicy
from packages.domain.clock import Clock
from packages.domain.continuous_composition_contracts import FORWARD_CLOSURE_SCHEMA
from packages.domain.continuous_engine_contracts import ContinuousEngineInputs, ContinuousEngineSpec
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
from packages.domain.continuous_persistence_contracts import (
    CONTINUOUS_COMMIT_SCHEMA,
    ContinuousAccountCommit,
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.continuous_runtime_source_contracts import (
    RUNTIME_SOURCE_SCHEMA,
    ContinuousRuntimeSourceDescriptor,
    runtime_producer_map,
)
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.daily_runtime_contracts import RuntimeProducerSpec
from packages.domain.engine_contracts import DailyRiskPolicy
from packages.domain.forward_capture_contracts import CapturePublication, ForwardCaptureRequest
from packages.domain.forward_contracts import ForwardSource
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import CashFlowKind, LedgerCashFlow, create_cash_flow
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
    OperationalControlTransition,
)
from packages.domain.personal_contracts import VersionPin, content_digest, require_utc
from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.domain.research_job_contracts import require_identifier
from packages.domain.runtime_operating_contracts import CLOCK_SCHEMA, RuntimeClockObservation
from packages.domain.stateful_venue_contracts import VenueModel, VenueSourceReference
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.applied_reconciliation_schema import APPLIED_RECONCILIATION_TABLES
from packages.persistence.continuous_account import ResolvedContinuousAccount, SqlContinuousAccount
from packages.persistence.continuous_account_schema import CONTINUOUS_ACCOUNT_TABLES
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_forward_sources import SqlContinuousForwardSources
from packages.persistence.continuous_reconciliation_publication import (
    SqlContinuousReconciliationPublication,
)
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.continuous_venue_sources import SqlContinuousVenueSources
from packages.persistence.daily_runtime_risk import (
    ResolvedDailyRuntimeSnapshot,
    SqlDailyRuntimeRisk,
)
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import (
    JOURNAL_TABLES,
    journal_appends,
    journal_entries,
    journal_streams,
)
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.runtime_operating_evidence import SqlRuntimeOperatingEvidence
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from packages.persistence.runtime_owner_commands import SqlRuntimeOwnerCommands
from packages.persistence.runtime_owner_dependencies import SqlRuntimeOwnerDependencies
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)
from packages.persistence.stateful_venue import SqlStatefulVenue


@dataclass(frozen=True, slots=True)
class SyntheticSessionGenesis:
    """Original owners and authenticated genesis; its startup fence is released."""

    scope: ContinuousAccountScope
    account: SqlContinuousAccount
    daily: SqlDailyRuntimeRisk
    runtime_sources: SqlContinuousRuntimeSources
    owners: SqlRuntimeOwnerDependencies
    venue: SqlStatefulVenue
    control: OperationalControlTransition
    restored: ResolvedContinuousAccount
    inventory: ResolvedDailyRuntimeSnapshot
    lease: AccountLease
    release: AccountLeaseRelease


@dataclass(frozen=True, slots=True)
class SyntheticSessionOwners:
    """New same-process owners; the caller retains the supplied lease lifecycle."""

    account: SqlContinuousAccount
    runtime: SqlContinuousRuntimeSources
    daily: SqlDailyRuntimeRisk
    venue_sources: SqlContinuousVenueSources
    owners: SqlRuntimeOwnerDependencies


def _assemble_synthetic_owners(
    runtime: SqlContinuousRuntimeSources,
    *,
    scope: ContinuousAccountScope,
    fence: AccountFence,
    owner_id: str,
    venue_sources: SqlContinuousVenueSources | None = None,
    commands: SqlRuntimeOwnerCommands | None = None,
) -> SyntheticSessionOwners:
    """One constructor sequence for genesis and a new current owner graph.

    The caller has already selected the original runtime services and fence.
    Only genesis creates the source/disabled-command owners here; reconstruction
    retains those exact services and creates new account-bound owners around them.
    This helper does not restore, publish, or manage the caller's lease.
    """
    engine, coordinator = runtime.engine, runtime.coordinator
    artifacts, accounting = runtime.artifacts, runtime.accounting
    daily = SqlDailyRuntimeRisk(
        engine, coordinator=coordinator, codec=codec, producers=runtime, accounting=accounting
    )
    preparer = ContinuousAccountTransitionPreparer(
        accounting=accounting, strategy=runtime.strategy, runtime_evidence=runtime
    )
    if venue_sources is None:
        venue_sources = SqlContinuousVenueSources(
            engine,
            artifacts=artifacts,
            codec=codec,
            resolver=VenueReconciliationResolver(
                transition_resolver=ContinuousReconciliationTransitionResolver(
                    accounting=accounting
                )
            ),
            scope=ReconciliationScope(
                scope.account_id,
                runtime.venue_model.venue_id,
                "stateful_simulation",
                scope.account_binding_sha256,
                "stateful_simulation",
            ),
            model=runtime.venue_model,
        )
    composer = SqlContinuousCommitComposer(
        engine,
        daily=daily,
        coordinator=coordinator,
        forward_sources=runtime.forward_sources,
        artifacts=artifacts,
        codec=codec,
        producer_history=runtime,
        fence=fence,
        benchmark_instrument_id=runtime.benchmark_instrument_id,
        venue_sources=venue_sources,
        accounting=accounting,
    )
    account = SqlContinuousAccount(
        engine,
        coordinator=coordinator,
        journal=SqlDurableJournal(
            engine, codec=codec, record_types={CONTINUOUS_COMMIT_SCHEMA: ContinuousAccountCommit}
        ),
        artifacts=artifacts,
        codec=codec,
        preparer=preparer,
        composer=composer,
    )
    runtime.bind_stores(accounts=account, daily=daily)
    publisher = SqlContinuousReconciliationPublication(
        engine,
        account=account,
        composer=composer,
        coordinator=coordinator,
        sources=venue_sources,
        artifacts=artifacts,
        codec=codec,
        accounting=accounting,
    )
    runtime.bind_reconciliation(publisher)
    if commands is None:
        commands = SqlRuntimeOwnerCommands(
            engine,
            codec=codec,
            authenticator=LocalRuntimeOwnerAuthenticator(
                LocalOperatorSecurity(
                    enabled=False,
                    transport_is_loopback_scoped=False,
                    operator_id=owner_id,
                    configured_secret="",
                )
            ),
        )
    owners = SqlRuntimeOwnerDependencies(
        engine,
        accounts=account,
        daily=daily,
        publisher=publisher,
        commands=commands,
        artifacts=artifacts,
        codec=codec,
    )
    runtime.bind_owner_dependencies(owners)
    return SyntheticSessionOwners(account, runtime, daily, venue_sources, owners)


def _database_path(engine: sa.Engine) -> Path:
    if type(engine) is not sa.Engine or engine.dialect.name != "sqlite":
        raise ValueError("fresh synthetic genesis requires original SQLite engines")
    with engine.connect() as connection:
        rows = connection.exec_driver_sql("PRAGMA database_list").fetchmany(3)
        # SQLite introspection can open an empty internal temp namespace. A
        # temporary object could shadow the main financial tables, so the fresh
        # genesis contract requires that namespace to contain no objects.
        temporary = connection.exec_driver_sql("SELECT 1 FROM sqlite_temp_master LIMIT 1").first()
    main = [row for row in rows if row[1] == "main"]
    if (
        len(rows) > 2
        or len(main) != 1
        or any(row[1] not in ("main", "temp") for row in rows)
        or temporary is not None
        or type(main[0][2]) is not str
        or not main[0][2]
        or not Path(main[0][2]).is_absolute()
    ):
        raise ValueError("fresh synthetic genesis requires one explicit file database")
    return Path(main[0][2]).resolve(strict=True)


def _require_empty(connection: sa.Connection, tables: tuple[sa.Table, ...]) -> None:
    for table in tables:
        if connection.execute(sa.select(sa.literal(1)).select_from(table).limit(1)).first():
            raise ValueError("fresh synthetic genesis cannot adopt existing or partial state")


def _require_fresh_stores(
    bootstrap: SyntheticBootstrapCapture,
    account_engine: sa.Engine,
    venue_engine: sa.Engine,
    account_artifacts: LocalResearchArtifactStore,
    venue_artifacts: LocalResearchArtifactStore,
) -> None:
    _require_fresh_capture_stores(
        bootstrap.closure.publications,
        account_engine,
        venue_engine,
        account_artifacts,
        venue_artifacts,
    )


def _require_fresh_capture_stores(
    publications: tuple[CapturePublication, ...],
    account_engine: sa.Engine,
    venue_engine: sa.Engine,
    account_artifacts: LocalResearchArtifactStore,
    venue_artifacts: LocalResearchArtifactStore,
) -> None:
    if _database_path(account_engine).samefile(_database_path(venue_engine)):
        raise ValueError("synthetic account and venue require independent databases")
    if (
        type(account_artifacts) is not LocalResearchArtifactStore
        or type(venue_artifacts) is not LocalResearchArtifactStore
        or account_artifacts._root.samefile(venue_artifacts._root)
    ):
        raise ValueError("synthetic account and venue require independent private object stores")
    expected_objects = {
        publication.record.raw_object.object_sha256 + ".json" for publication in publications
    }
    seen = set()
    for path in account_artifacts._root.iterdir():
        if path.is_symlink() or not path.is_file() or path.name not in expected_objects:
            raise ValueError("fresh account objects must contain only the supplied captures")
        seen.add(path.name)
    if seen != expected_objects or next(venue_artifacts._root.iterdir(), None) is not None:
        raise ValueError("fresh synthetic object inventory differs")
    heads = {
        publication.record.request.journal_key.semantic_sha256: (
            publication.journal_receipt.committed_head
        )
        for publication in publications
    }
    with account_engine.connect() as connection:
        _require_empty(
            connection,
            (
                *DAILY_RUNTIME_TABLES,
                *CONTINUOUS_ACCOUNT_TABLES,
                *APPLIED_RECONCILIATION_TABLES,
                phase2_account_leases,
                phase2_account_lease_heads,
                phase2_account_lease_releases,
                phase5_operational_control_transitions,
                phase5_operational_control_heads,
                phase5_operational_control_completions,
            ),
        )
        rows = connection.execute(sa.select(journal_streams).limit(len(heads) + 1)).mappings().all()
        if len(rows) != len(heads) or any(
            row["key_sha256"] not in heads
            or row["last_sequence"] != heads[row["key_sha256"]].sequence
            or row["last_entry_sha256"] != heads[row["key_sha256"]].entry_sha256
            for row in rows
        ):
            raise ValueError("fresh account journal must end at the supplied capture receipts")
        for table in (journal_appends, journal_entries):
            count = connection.scalar(sa.select(sa.func.count()).select_from(table))
            if count != len(publications):
                raise ValueError("fresh capture journal contains an additional or missing record")
    with venue_engine.connect() as connection:
        _require_empty(connection, JOURNAL_TABLES)


def _require_input_profile(inputs: ContinuousEngineInputs) -> None:
    if type(inputs) is not ContinuousEngineInputs:
        raise ValueError("original synthetic continuous inputs required")
    inputs.__post_init__()
    spec = inputs.spec
    spec.__post_init__()
    configuration = ReferenceConfiguration(lookback=2)
    if (
        spec.environment != "stateful_simulation"
        or spec.source_mode != "synthetic_observed"
        or spec.live_authorized is not False
        or spec.account_privileges != "CASH"
        or spec.initial_cash != Decimal("10000")
        or spec.calendar.calendar_id != SYNTHETIC_CALENDAR
        or len(spec.instruments) != 1
        or spec.strategy_configuration != configuration
        or spec.strategy
        != VersionPin(
            "strategy",
            "personal-daily-reference/1",
            content_digest((configuration, "reference-callback-adapter/1")),
        )
        or spec.risk_policy != DailyRiskPolicy(policy_id="personal-daily-stateful-simulation/1")
        or spec.execution_policy
        != ExecutionPolicy(
            spec.execution_policy.settlement_calendar,
            model_id="observed-facts-v1",
            settlement_model="observed-only-v1",
            correction_settlement="explicit-only-v1",
            terminal_model="observed-only-v1",
        )
        or (spec.max_events, spec.max_output_bytes, spec.max_wall_seconds, spec.max_memory_bytes)
        != (100000, 33554432, 30, 4294967296)
        or spec.account_binding_sha256
        != content_digest(
            (
                "synthetic-continuous-account-binding/1",
                spec.account_id,
                spec.deployment_id,
                spec.instruments,
            )
        )
    ):
        raise ValueError("synthetic genesis requires the original live-disabled default profile")


def _require_profile(bootstrap: SyntheticBootstrapCapture) -> None:
    if (
        type(bootstrap) is not SyntheticBootstrapCapture
        or type(bootstrap.inputs) is not ContinuousEngineInputs
    ):
        raise ValueError("original synthetic bootstrap capture required")
    _require_input_profile(bootstrap.inputs)
    if (
        type(bootstrap.closure) is not ContinuousForwardClosure
        or bootstrap.closure.account_id != bootstrap.inputs.spec.account_id
        or bootstrap.closure.evidence_class != "synthetic_fixture"
    ):
        raise ValueError("synthetic genesis requires the original live-disabled default profile")
    bootstrap.closure.__post_init__()


def _synthetic_genesis_values(
    spec: ContinuousEngineSpec, venue_pin: VersionPin
) -> tuple[LedgerCashFlow, VenueModel, ContinuousAccountScope]:
    seed = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=spec.initial_cash,
        effective_at=spec.initialized_at,
        recorded_at=spec.initialized_at,
        external_reference=canonical_id("initial-capital", spec.run_id),
    )
    model = VenueModel(
        account_id=spec.account_id,
        venue_id="synthetic-session-venue-1",
        producer=venue_pin,
        instruments=spec.instruments,
        sources=(
            ForwardSource(
                "synthetic-session-venue-source/1",
                "fixture",
                "synthetic",
                spec.account_id,
                "synthetic-identity-model/1",
                "allowed",
                "synthetic-rights-model/1",
                "not_required",
                "synthetic-entitlement-model/1",
            ),
        ),
        source_mode="synthetic_fixture",
        execution_policy=replace(spec.execution_policy, model_id="stateful-venue-facts-v1"),
        initial_cash_flow=seed,
    )
    scope = ContinuousAccountScope(spec.account_id, spec.account_binding_sha256, spec.deployment_id)
    return seed, model, scope


def _publish_synthetic_genesis_under_lease(
    bootstrap: SyntheticBootstrapCapture,
    *,
    spec: ContinuousEngineSpec,
    benchmark: str | None,
    daily_request: ForwardCaptureRequest,
    seed: LedgerCashFlow,
    model: VenueModel,
    scope: ContinuousAccountScope,
    forward: SqlContinuousForwardSources,
    coordinator: SqlAccountCoordinator,
    lease: AccountLease,
    account_engine: sa.Engine,
    venue_engine: sa.Engine,
    account_artifacts: LocalResearchArtifactStore,
    venue_artifacts: LocalResearchArtifactStore,
    clock: Clock,
    monotonic_now_ns: Callable[[], int],
    epoch_id: str,
    owner_id: str,
    venue_pin: VersionPin,
    quote_producer: VersionPin,
) -> tuple[
    SqlContinuousAccount,
    SqlDailyRuntimeRisk,
    SqlContinuousRuntimeSources,
    SqlRuntimeOwnerDependencies,
    SqlStatefulVenue,
    OperationalControlTransition,
    ResolvedContinuousAccount,
    ResolvedDailyRuntimeSnapshot,
]:
    """Original genesis publication sequence; the caller owns acquire/release."""
    accounting = PersonalAccounting()
    strategy = ReferenceStrategy(
        reserve_fraction=spec.risk_policy.adverse_reserve_fraction,
        fee_per_share=spec.risk_policy.fee_per_share,
    )
    authority = content_digest(("synthetic-session-genesis/1", spec, venue_pin, quote_producer))
    control = SqlOperationalControlRepository(engine=account_engine, clock=clock).apply(
        OperationalControlCommand(
            spec.account_id,
            canonical_id("synthetic-initialize-halted", spec.run_id),
            OperationalControlCommandKind.INITIALIZE_HALTED,
            OperationalControlState.HALTED,
            OperationalControlActor(owner_id, OperationalControlActorKind.SYSTEM, authority, None),
            "SYNTHETIC_INITIALIZE_HALTED",
            authority,
            spec.initialized_at,
        )
    )
    operating = SqlRuntimeOperatingEvidence(
        account_engine,
        artifacts=account_artifacts,
        codec=codec,
        clock_sampler=RuntimeClockSampler.simulation_model(
            scope=scope,
            utc_now=clock.now,
            monotonic_now_ns=monotonic_now_ns,
            epoch_provider=lambda: epoch_id,
        ),
        journal=SqlDurableJournal(
            account_engine, codec=codec, record_types={CLOCK_SCHEMA: RuntimeClockObservation}
        ),
    )
    runtime = SqlContinuousRuntimeSources(
        account_engine,
        coordinator=coordinator,
        journal=SqlDurableJournal(
            account_engine,
            codec=codec,
            record_types={RUNTIME_SOURCE_SCHEMA: ContinuousRuntimeSourceDescriptor},
        ),
        artifacts=account_artifacts,
        codec=codec,
        forward_sources=forward,
        operating=operating,
        accounting=accounting,
        strategy=strategy,
        venue_model=model,
        venue_reference=VenueSourceReference(
            model.producer,
            model.semantic_sha256,
            account_artifacts.put(codec.encode_record(model)),
        ),
        producer_map=runtime_producer_map(
            account_id=spec.account_id,
            venue_model=model,
            daily=RuntimeProducerSpec(
                role="daily_inputs",
                producer=daily_request.producer,
                provider_id=daily_request.source.provider,
                source_environment=daily_request.source.environment,
                account_scope=spec.account_id,
            ),
            quotes=RuntimeProducerSpec(
                role="quotes",
                producer=quote_producer,
                provider_id="etrade",
                source_environment="production",
                account_scope=spec.account_id,
            ),
        ),
        benchmark_instrument_id=benchmark,
        current_fence=lambda: lease.fence,
    )
    assembled = _assemble_synthetic_owners(
        runtime, scope=scope, fence=lease.fence, owner_id=owner_id
    )
    account, daily, owners = assembled.account, assembled.daily, assembled.owners
    preparer = account.preparer
    if account.restore(scope) is not None:
        raise ValueError("synthetic account already has a canonical predecessor")
    transition = preparer.prepare_initialize(
        command_id=canonical_id("synthetic-genesis", spec.run_id),
        inputs=bootstrap.inputs,
        source_closure_sha256=bootstrap.closure.semantic_sha256,
    )
    state = transition.checkpoint.state
    if (
        state.cash_flows != (seed,)
        or state.commitments
        or state.submissions
        or state.broker_events
        or transition.checkpoint.runtime_decisions
    ):
        raise ValueError("prepared synthetic funding must equal the independent venue seed")
    venue = SqlStatefulVenue(
        venue_engine, model=model, artifacts=venue_artifacts, codec=codec, accounting=accounting
    )
    venue_genesis = venue.initialize()
    if venue_genesis.state.accounting.cash_flows != (seed,) or venue_genesis.state.sequence != 0:
        raise ValueError("independent synthetic venue genesis differs")
    prepared = account.prepare(
        transition,
        scope=scope,
        previous=None,
        source_evidence=ContinuousEvidenceRef(
            FORWARD_CLOSURE_SCHEMA,
            account_artifacts.put(codec.encode_record(bootstrap.closure)),
            bootstrap.closure.semantic_sha256,
        ),
    )
    with account.write_transaction() as connection:
        receipt = account.commit_in_transaction(connection, prepared=prepared, fence=lease.fence)
    restored = account.restore(scope)
    if restored is None or restored.receipt != receipt or receipt.commit.sequence != 1:
        raise ValueError("synthetic genesis did not restore its original receipt")
    account.require_resolved(restored)
    inventory = daily.resolve_snapshot(
        daily.read_snapshot(account_id=spec.account_id, fence=lease.fence)
    )
    if (
        inventory.assignment is not None
        or inventory.assignment_rows
        or inventory.admissions
        or inventory.obligations.bindings
        or inventory.attempts
        or inventory.attempt_envelopes
        or inventory.observed_groups
        or inventory.control != control
        or control.effective_state is not OperationalControlState.HALTED
    ):
        raise ValueError("synthetic genesis requires empty B and original HALTED control")
    return account, daily, runtime, owners, venue, control, restored, inventory


def initialize_synthetic_session(
    bootstrap: SyntheticBootstrapCapture,
    *,
    account_engine: sa.Engine,
    venue_engine: sa.Engine,
    account_artifacts: LocalResearchArtifactStore,
    venue_artifacts: LocalResearchArtifactStore,
    clock: Clock,
    monotonic_now_ns: Callable[[], int],
    epoch_id: str,
    owner_id: str,
    venue_pin: VersionPin,
    quote_producer: VersionPin,
) -> SyntheticSessionGenesis:
    """Publish one real C genesis with empty B and an independent funded venue.

    All stores must be exclusively caller-owned and fresh except for the exact
    captured warmup. No adoption/retry or cross-database atomicity is promised.
    After any acquired fence, release is attempted even if construction, original
    validation, publication, or restore raises. Release errors remain failures.
    """
    _require_profile(bootstrap)
    require_identifier(owner_id, "synthetic startup owner")
    require_identifier(epoch_id, "modeled clock epoch")
    for pin in (venue_pin, quote_producer):
        if type(pin) is not VersionPin:
            raise ValueError("exact synthetic producer pins required")
        pin.__post_init__()
    spec = bootstrap.inputs.spec
    benchmark = next(
        (instrument_id for instrument_id, symbol in spec.instruments if symbol == "SPY"), None
    )
    now = clock.now()
    require_utc(now, "synthetic initialization clock")
    if now != spec.initialized_at or not callable(monotonic_now_ns):
        raise ValueError("explicit modeled clock must begin at initialization")
    _require_fresh_stores(
        bootstrap, account_engine, venue_engine, account_artifacts, venue_artifacts
    )
    forward = SqlContinuousForwardSources(
        account_engine, artifacts=account_artifacts, codec=codec, evidence_class="synthetic_fixture"
    )
    resolved = forward.resolve(bootstrap.closure)
    if (
        resolved.state != bootstrap.state
        or compile_continuous_bootstrap(
            spec,
            resolved.state,
            bootstrap.closure.observation_ids,
            bootstrap.closure.admitted_at,
            benchmark_instrument_id=benchmark,
            capture_evidence_class="synthetic_fixture",
        )
        != bootstrap.inputs
    ):
        raise ValueError("synthetic bootstrap differs from its original retained captures")
    daily_request = bootstrap.closure.publications[0].record.request
    if any(
        (
            p.record.request.producer,
            p.record.request.source.provider,
            p.record.request.source.environment,
        )
        != (daily_request.producer, daily_request.source.provider, daily_request.source.environment)
        for p in bootstrap.closure.publications
    ):
        raise ValueError("synthetic bootstrap producer profile differs")
    seed, model, scope = _synthetic_genesis_values(spec, venue_pin)
    coordinator = SqlAccountCoordinator(
        account_id=spec.account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=account_engine,
            clock=clock,
            policy=AccountLeasePolicy(
                "synthetic-session-account-lease/1",
                "1",
                timedelta(seconds=60),
                timedelta(seconds=5),
                timedelta(seconds=10),
            ),
        ),
    )
    lease = coordinator.acquire(owner_id)
    primary: BaseException | None = None
    try:
        account, daily, runtime, owners, venue, control, restored, inventory = (
            _publish_synthetic_genesis_under_lease(
                bootstrap,
                spec=spec,
                benchmark=benchmark,
                daily_request=daily_request,
                seed=seed,
                model=model,
                scope=scope,
                forward=forward,
                coordinator=coordinator,
                lease=lease,
                account_engine=account_engine,
                venue_engine=venue_engine,
                account_artifacts=account_artifacts,
                venue_artifacts=venue_artifacts,
                clock=clock,
                monotonic_now_ns=monotonic_now_ns,
                epoch_id=epoch_id,
                owner_id=owner_id,
                venue_pin=venue_pin,
                quote_producer=quote_producer,
            )
        )
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            release = coordinator.release(lease.fence)
            if coordinator.current() is not None:
                raise ValueError("synthetic startup did not release its original fence")
        except BaseException as cleanup:
            if primary is not None:
                raise BaseExceptionGroup(
                    "synthetic genesis and fence cleanup failed", [primary, cleanup]
                ) from None
            raise
    return SyntheticSessionGenesis(
        scope, account, daily, runtime, owners, venue, control, restored, inventory, lease, release
    )


def _require_genesis_owner_graph(genesis: SyntheticSessionGenesis) -> None:
    if (
        type(genesis) is not SyntheticSessionGenesis
        or type(genesis.account) is not SqlContinuousAccount
        or type(genesis.daily) is not SqlDailyRuntimeRisk
        or type(genesis.runtime_sources) is not SqlContinuousRuntimeSources
        or type(genesis.owners) is not SqlRuntimeOwnerDependencies
        or type(genesis.venue) is not SqlStatefulVenue
        or type(genesis.scope) is not ContinuousAccountScope
        or type(genesis.lease) is not AccountLease
        or type(genesis.release) is not AccountLeaseRelease
        or type(genesis.restored) is not ResolvedContinuousAccount
        or type(genesis.inventory) is not ResolvedDailyRuntimeSnapshot
        or type(genesis.control) is not OperationalControlTransition
        or type(genesis.account.preparer) is not ContinuousAccountTransitionPreparer
    ):
        raise ValueError("ORIGINAL_SYNTHETIC_GENESIS_OWNERS_REQUIRED")
    old = genesis.runtime_sources
    publisher = genesis.owners.publisher
    composer = genesis.account.composer
    commands = genesis.owners.commands
    if (
        type(publisher) is not SqlContinuousReconciliationPublication
        or type(composer) is not SqlContinuousCommitComposer
        or type(publisher.sources) is not SqlContinuousVenueSources
        or type(commands) is not SqlRuntimeOwnerCommands
        or type(commands.authenticator) is not LocalRuntimeOwnerAuthenticator
        or type(commands.authenticator.security) is not LocalOperatorSecurity
        or commands.authenticator.security._enabled is not False
        or type(old.coordinator) is not SqlAccountCoordinator
        or type(old.venue_model) is not VenueModel
        or type(old.operating) is not SqlRuntimeOperatingEvidence
        or type(old.operating.clock_sampler) is not RuntimeClockSampler
        or old.operating.clock_sampler.profile != "explicit_simulation_time_model"
        or old.operating.clock_sampler.scope != genesis.scope
        or type(old.forward_sources) is not SqlContinuousForwardSources
        or old.forward_sources.evidence_class != "synthetic_fixture"
        or type(old.artifacts) is not LocalResearchArtifactStore
        or old.accounts is not genesis.account
        or old.daily is not genesis.daily
        or old.publisher is not publisher
        or old.owner_dependencies is not genesis.owners
        or genesis.daily.producers is not old
        or genesis.owners.accounts is not genesis.account
        or genesis.owners.daily is not genesis.daily
        or publisher.account is not genesis.account
        or publisher.composer is not composer
        or composer.daily is not genesis.daily
        or composer.producer_history is not old
        or composer.venue_sources is not publisher.sources
        or composer.forward_sources is not old.forward_sources
        or composer.fence != genesis.lease.fence
        or publisher.sources.model is not old.venue_model
        or genesis.venue.model is not old.venue_model
        or genesis.venue.verified_sources is not None
        or genesis.account.preparer.runtime_evidence is not old
        or genesis.account.preparer.accounting is not old.accounting
        or genesis.account.preparer.strategy is not old.strategy
        or any(
            item.engine is not old.engine
            for item in (
                genesis.account,
                genesis.daily,
                publisher,
                publisher.sources,
                commands,
                old.forward_sources,
                old.operating,
            )
        )
        or any(
            item.codec is not codec
            for item in (
                genesis.account,
                genesis.daily,
                old,
                publisher,
                publisher.sources,
                commands,
                old.forward_sources,
                old.operating,
            )
        )
        or any(
            item.coordinator is not old.coordinator
            for item in (genesis.account, genesis.daily, composer, publisher)
        )
        or any(
            item.artifacts is not old.artifacts
            for item in (
                genesis.account,
                composer,
                publisher,
                publisher.sources,
                old.forward_sources,
                old.operating,
            )
        )
        or old.attempt_sources is not None
        or old.observed_hold_sources is not None
        or old._attempt_sources_binding is not None
        or old._observed_sources_binding is not None
        or old._observed_sources_pins is not None
    ):
        raise ValueError("ORIGINAL_SYNTHETIC_GENESIS_BINDINGS_REQUIRED")
    # The result record is a container, not a new authentication token. These
    # original owners authenticate its actual process-local restored values.
    genesis.account.require_resolved(genesis.restored)
    genesis.daily.require_resolved_snapshot(genesis.inventory)
    inputs = genesis.restored.checkpoint.inputs
    if type(inputs) is not ContinuousEngineInputs:
        raise ValueError("ORIGINAL_SYNTHETIC_GENESIS_INPUTS_REQUIRED")
    _require_input_profile(inputs)
    if (
        genesis.restored.receipt.commit.sequence != 1
        or genesis.restored.receipt.commit.scope != genesis.scope
        or genesis.restored.receipt.fence_reference.lease_sha256 != genesis.lease.semantic_sha256
        or genesis.scope.account_id != inputs.spec.account_id
        or genesis.scope.account_binding_sha256 != inputs.spec.account_binding_sha256
        or genesis.scope.stream_id != inputs.spec.deployment_id
        or genesis.restored.request != inputs
        or genesis.inventory.assignment is not None
        or genesis.inventory.assignment_rows
        or genesis.inventory.admissions
        or genesis.inventory.obligations.bindings
        or genesis.inventory.attempts
        or genesis.inventory.attempt_envelopes
        or genesis.inventory.observed_groups
        or genesis.inventory.control != genesis.control
        or genesis.control.effective_state is not OperationalControlState.HALTED
        or old.venue_model.account_id != genesis.scope.account_id
        or old.venue_model.source_mode != "synthetic_fixture"
        or old.venue_model.live_authorized is not False
        or genesis.release.fence != genesis.lease.fence
        or genesis.release.lease_sha256 != genesis.lease.semantic_sha256
    ):
        raise ValueError("HALTED_EMPTY_SYNTHETIC_GENESIS_REQUIRED")


def _require_current_synthetic_lease(genesis: SyntheticSessionGenesis, lease: AccountLease) -> None:
    if type(lease) is not AccountLease or lease.account_id != genesis.scope.account_id:
        raise ValueError("EXACT_SYNTHETIC_ACCOUNT_LEASE_REQUIRED")
    lease.__post_init__()
    receipt = genesis.account.coordinator.revalidate(lease.fence)
    if receipt.lease_sha256 != lease.semantic_sha256:
        raise ValueError("CURRENT_SYNTHETIC_LEASE_REVISION_REQUIRED")


def _reconstruct_synthetic_owner_graph(
    genesis: SyntheticSessionGenesis, *, lease: AccountLease
) -> SyntheticSessionOwners:
    """Construct only; each public caller separately authenticates its B scope."""
    old = genesis.runtime_sources
    runtime = SqlContinuousRuntimeSources(
        old.engine,
        coordinator=old.coordinator,
        journal=SqlDurableJournal(
            old.engine,
            codec=codec,
            record_types={RUNTIME_SOURCE_SCHEMA: ContinuousRuntimeSourceDescriptor},
        ),
        artifacts=old.artifacts,
        codec=codec,
        forward_sources=old.forward_sources,
        operating=old.operating,
        accounting=old.accounting,
        strategy=old.strategy,
        venue_model=old.venue_model,
        venue_reference=old.venue_reference,
        producer_map=old.producer_map,
        benchmark_instrument_id=old.benchmark_instrument_id,
        current_fence=lambda: lease.fence,
    )
    return _assemble_synthetic_owners(
        runtime,
        scope=genesis.scope,
        fence=lease.fence,
        owner_id=lease.owner_id,
        venue_sources=genesis.owners.publisher.sources,
        commands=genesis.owners.commands,
    )


def reconstruct_synthetic_session_owners(
    genesis: SyntheticSessionGenesis, *, lease: AccountLease
) -> SyntheticSessionOwners:
    """Reconstruct current owners from a genuine same-process synthetic genesis.

    The caller supplies and retains responsibility for its active original
    lease, including release on failure. This function does not acquire, renew,
    release, authenticate commands, initialize stores, or publish financial or
    control facts. Original coordinator validation may update its observation
    watermark. No process restart/configuration loader is supplied here.

    The old graph stays bound to its released startup fence. New source/account
    owners reuse its original modeled services; complete restore and current B
    validation must still prove this exact HALTED genesis before return.
    """
    _require_genesis_owner_graph(genesis)
    _require_current_synthetic_lease(genesis, lease)
    result = _reconstruct_synthetic_owner_graph(genesis, lease=lease)
    restored = result.account.restore(genesis.scope)
    if (
        restored is None
        or restored.receipt != genesis.restored.receipt
        or restored.checkpoint != genesis.restored.checkpoint
    ):
        raise ValueError("CURRENT_SYNTHETIC_GENESIS_DIFFERS")
    result.account.require_resolved(restored)
    inventory = result.daily.resolve_snapshot(
        result.daily.read_snapshot(account_id=genesis.scope.account_id, fence=lease.fence)
    )
    if (
        inventory.assignment is not None
        or inventory.assignment_rows
        or inventory.admissions
        or inventory.obligations.bindings
        or inventory.attempts
        or inventory.attempt_envelopes
        or inventory.observed_groups
        or inventory.control is None
        or inventory.control != genesis.control
        or inventory.control.effective_state is not OperationalControlState.HALTED
    ):
        raise ValueError("CURRENT_HALTED_EMPTY_SYNTHETIC_GENESIS_REQUIRED")
    _require_genesis_owner_graph(genesis)
    _require_current_synthetic_lease(genesis, lease)
    return result


def reconstruct_selected_synthetic_session_owners(
    genesis: SyntheticSessionGenesis, *, lease: AccountLease
) -> SyntheticSessionOwners:
    """Authenticate only the installed disabled generation-one HALTED selection.

    This same-process path reconstructs owners under a caller-managed current
    lease. The original request is historical evidence, even after its expiry;
    it is never prepared, authenticated, published or treated as current command
    authority again. The existing empty-B reconstruction contract is unchanged.

    No assignment, control, journal, venue or financial fact is published here.
    Current snapshot/fence rechecks can update the coordinator's observation
    watermark. They neither renew its lease nor extend an original deadline.
    Later session operations retain all of their own current-state checks.
    """
    _require_genesis_owner_graph(genesis)
    _require_current_synthetic_lease(genesis, lease)
    result = _reconstruct_synthetic_owner_graph(genesis, lease=lease)
    restored = result.account.restore(genesis.scope)
    if (
        restored is None
        or restored.receipt != genesis.restored.receipt
        or restored.checkpoint != genesis.restored.checkpoint
    ):
        raise ValueError("CURRENT_SELECTED_SYNTHETIC_GENESIS_DIFFERS")
    result.account.require_resolved(restored)
    current = result.daily.resolve_snapshot(
        result.daily.read_snapshot(account_id=genesis.scope.account_id, fence=lease.fence)
    )
    assignment = current.assignment
    spec = restored.checkpoint.inputs.spec
    if (
        assignment is None
        or current.assignment_rows != (assignment,)
        or assignment.account_id != genesis.scope.account_id
        or assignment.account_binding_sha256 != genesis.scope.account_binding_sha256
        or assignment.generation != 1
        or assignment.previous_assignment_sha256 is not None
        or assignment.enabled_for_new_exposure is not False
        or assignment.live_authorized is not False
        or assignment.policy != spec.risk_policy
        or assignment.strategy != spec.strategy
        or assignment.configuration_sha256 != content_digest(spec.strategy_configuration)
        or assignment.instrument_symbols != spec.instruments
        or assignment.producer_map_sha256 != result.runtime.producer_map.semantic_sha256
        or current.admissions
        or current.obligations.bindings
        or current.attempts
        or current.attempt_envelopes
        or current.observed_groups
        or current.control is None
        or current.control != genesis.control
        or current.control.effective_state is not OperationalControlState.HALTED
    ):
        raise ValueError("CURRENT_HALTED_DISABLED_INITIAL_SYNTHETIC_SELECTION_REQUIRED")
    associations = SqlRuntimeOwnerAssociations(owner_dependencies=result.owners)
    association = associations.read(genesis.scope, current=current, assignment_generation=1)
    associations.require_association(association)
    if (
        association.dependencies.previous != genesis.restored.receipt
        or association.dependencies.proposed != assignment
        or association.dependencies.previous_assignment_sha256 is not None
        or association.canonical.receipt != genesis.restored.receipt
        or association.checkpoint != genesis.restored.checkpoint
        or association.prefix.before_assignment is not None
        or association.prefix.after_assignment != assignment
        or association.reconciliation is not None
    ):
        raise ValueError("ORIGINAL_DISABLED_SYNTHETIC_SELECTION_HISTORY_REQUIRED")
    # Association checks deliberately permit later heads and expired original
    # requests. Separately recheck the selected current C/B footprint and fence
    # in one transaction so changes after capture cannot qualify this result.
    with _repeatable_read_transaction(result.account.engine) as connection:
        associations.recheck_in_transaction(connection, association)
        result.account.recheck_in_transaction(connection, restored, require_current=True)
        result.daily.recheck_snapshot_in_transaction(connection, current, fence=lease.fence)
    _require_genesis_owner_graph(genesis)
    _require_current_synthetic_lease(genesis, lease)
    return result
