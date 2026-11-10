"""Prepare and publish one disabled initial synthetic selection.

Authentication and request retention are separate caller responsibilities. This
join consumes the original request journal through the existing account owners;
it never issues a local session, authenticates a command, enables exposure,
re-arms controls, or manages the caller's lease. Modeled fixture time is not a
bridge from real operator authentication to accelerated simulation time.
"""

from datetime import datetime

from apps.trader.synthetic_session_genesis import (
    SyntheticSessionGenesis,
    SyntheticSessionOwners,
    _require_current_synthetic_lease,
    _require_genesis_owner_graph,
)
from packages.domain.account_coordinator import AccountLease
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.domain.durable_journal_contracts import JournalReceipt
from packages.domain.engine_contracts import DailyRiskPolicy
from packages.domain.operational_control import OperationalControlState
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.persistence.continuous_account import ResolvedContinuousAccount, SqlContinuousAccount
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.daily_runtime_risk import (
    ResolvedDailyRuntimeSnapshot,
    SqlDailyRuntimeRisk,
)
from packages.persistence.runtime_assignment_publication import SqlRuntimeAssignmentPublication
from packages.persistence.runtime_owner_dependencies import (
    PreparedRuntimeOwnerDependencies,
    SqlRuntimeOwnerDependencies,
)


def _require_owners(
    genesis: SyntheticSessionGenesis, owners: SyntheticSessionOwners, lease: AccountLease
) -> None:
    _require_genesis_owner_graph(genesis)
    _require_current_synthetic_lease(genesis, lease)
    if (
        type(owners) is not SyntheticSessionOwners
        or type(owners.account) is not SqlContinuousAccount
        or type(owners.daily) is not SqlDailyRuntimeRisk
        or type(owners.runtime) is not SqlContinuousRuntimeSources
        or type(owners.owners) is not SqlRuntimeOwnerDependencies
        or type(owners.account.composer) is not SqlContinuousCommitComposer
    ):
        raise ValueError("EXACT_SYNTHETIC_SELECTION_OWNERS_REQUIRED")
    runtime, old = owners.runtime, genesis.runtime_sources
    if (
        owners.account is genesis.account
        or runtime.accounts is not owners.account
        or runtime.daily is not owners.daily
        or runtime.owner_dependencies is not owners.owners
        or owners.daily.producers is not runtime
        or owners.owners.accounts is not owners.account
        or owners.owners.daily is not owners.daily
        or owners.owners.producer is not runtime
        or owners.owners.publisher is not runtime.publisher
        or owners.owners.commands is not genesis.owners.commands
        or owners.venue_sources is not genesis.owners.publisher.sources
        or owners.account.composer.venue_sources is not owners.venue_sources
        or owners.account.composer.producer_history is not runtime
        or owners.account.composer.daily is not owners.daily
        or owners.account.composer.fence != lease.fence
        or runtime.current_fence() != lease.fence
        or runtime.coordinator is not old.coordinator
        or owners.account.coordinator is not old.coordinator
        or owners.daily.coordinator is not old.coordinator
        or runtime.engine is not old.engine
        or owners.account.engine is not old.engine
        or owners.daily.engine is not old.engine
        or runtime.artifacts is not old.artifacts
        or runtime.codec is not old.codec
        or runtime.forward_sources is not old.forward_sources
        or runtime.operating is not old.operating
        or runtime.accounting is not old.accounting
        or runtime.strategy is not old.strategy
        or runtime.venue_model is not old.venue_model
        or runtime.venue_reference is not old.venue_reference
        or runtime.producer_map is not old.producer_map
        or runtime.benchmark_instrument_id != old.benchmark_instrument_id
    ):
        raise ValueError("ORIGINAL_SYNTHETIC_SELECTION_BINDINGS_REQUIRED")


def _current(
    genesis: SyntheticSessionGenesis, owners: SyntheticSessionOwners, lease: AccountLease
) -> tuple[ResolvedContinuousAccount, ResolvedDailyRuntimeSnapshot]:
    _require_owners(genesis, owners, lease)
    previous = owners.account.restore(genesis.scope)
    if (
        previous is None
        or previous.receipt != genesis.restored.receipt
        or previous.checkpoint != genesis.restored.checkpoint
    ):
        raise ValueError("SYNTHETIC_SELECTION_REQUIRES_ORIGINAL_C1")
    owners.account.require_resolved(previous)
    current = owners.daily.resolve_snapshot(
        owners.daily.read_snapshot(account_id=genesis.scope.account_id, fence=lease.fence)
    )
    if (
        current.assignment is not None
        or current.assignment_rows
        or current.admissions
        or current.obligations.bindings
        or current.attempts
        or current.attempt_envelopes
        or current.observed_groups
        or current.control != genesis.control
        or current.control is None
        or current.control.effective_state is not OperationalControlState.HALTED
    ):
        raise ValueError("SYNTHETIC_SELECTION_REQUIRES_HALTED_EMPTY_B")
    return previous, current


def _default_synthetic_initial_assignment(
    *,
    account_id: str,
    account_binding_sha256: str,
    policy: DailyRiskPolicy,
    strategy: VersionPin,
    configuration_sha256: str,
    instrument_symbols: tuple[tuple[str, str], ...],
    producer_map_sha256: str,
    effective_at: datetime,
) -> RuntimeRiskAssignment:
    return RuntimeRiskAssignment(
        account_id=account_id,
        account_binding_sha256=account_binding_sha256,
        generation=1,
        policy=policy,
        strategy=strategy,
        configuration_sha256=configuration_sha256,
        instrument_symbols=instrument_symbols,
        producer_map_sha256=producer_map_sha256,
        effective_at=effective_at,
        previous_assignment_sha256=None,
        enabled_for_new_exposure=False,
        live_authorized=False,
    )


_DEFAULT_SYNTHETIC_INITIAL_ASSIGNMENT = _default_synthetic_initial_assignment


def prepare_synthetic_initial_selection(
    genesis: SyntheticSessionGenesis,
    *,
    owners: SyntheticSessionOwners,
    lease: AccountLease,
) -> PreparedRuntimeOwnerDependencies:
    """Retain the original bounded dependency bundle; this installs nothing.

    The exact current C1 supplies policy, strategy and configuration. The caller
    must independently authenticate and retain the exact command referencing
    this bundle. Its original deadline and lease revision are never refreshed.
    """
    assignment_builder = _DEFAULT_SYNTHETIC_INITIAL_ASSIGNMENT
    if _default_synthetic_initial_assignment is not assignment_builder:
        raise RuntimeError("SYNTHETIC_INITIAL_ASSIGNMENT_BINDING_CHANGED")
    previous, current = _current(genesis, owners, lease)
    spec = previous.checkpoint.inputs.spec
    proposed = assignment_builder(
        account_id=genesis.scope.account_id,
        account_binding_sha256=genesis.scope.account_binding_sha256,
        policy=spec.risk_policy,
        strategy=spec.strategy,
        configuration_sha256=content_digest(spec.strategy_configuration),
        instrument_symbols=spec.instruments,
        producer_map_sha256=owners.runtime.producer_map.semantic_sha256,
        effective_at=current.raw.receipt.validated_at,
    )
    dependencies = owners.owners.prepare_dependencies(
        previous=previous, proposed=proposed, fence=lease.fence
    )
    owners.owners.require_prepared(dependencies)
    _require_owners(genesis, owners, lease)
    return dependencies


def publish_synthetic_initial_selection(
    genesis: SyntheticSessionGenesis,
    *,
    owners: SyntheticSessionOwners,
    lease: AccountLease,
    dependencies: PreparedRuntimeOwnerDependencies,
    request: JournalReceipt,
) -> RuntimeRiskAssignment:
    """Install only the separately retained initial request through its owners.

    A JournalReceipt is a locator, not permission: the reader reloads the exact
    durable request and rederives all dependencies. A copied prepared bundle
    fails its original owner check. A second call after installation is denied
    by the initial-empty-B requirement; it does not create an implicit retry.
    Failure preserves the retained request and immutable dependency object.
    The caller retains responsibility for releasing its original fence.
    """
    _require_owners(genesis, owners, lease)
    owners.owners.require_prepared(dependencies)
    if type(request) is not JournalReceipt:
        raise ValueError("EXACT_RETAINED_SYNTHETIC_SELECTION_REQUEST_REQUIRED")
    request.__post_init__()
    previous, _ = _current(genesis, owners, lease)
    proposed = dependencies.record.proposed
    spec = previous.checkpoint.inputs.spec
    if (
        dependencies.previous.receipt != previous.receipt
        or dependencies.record.scope != genesis.scope
        or dependencies.record.previous_assignment_sha256 is not None
        or proposed.generation != 1
        or proposed.previous_assignment_sha256 is not None
        or proposed.enabled_for_new_exposure is not False
        or proposed.live_authorized is not False
        or proposed.policy != spec.risk_policy
        or proposed.strategy != spec.strategy
        or proposed.configuration_sha256 != content_digest(spec.strategy_configuration)
        or proposed.instrument_symbols != spec.instruments
        or proposed.producer_map_sha256 != owners.runtime.producer_map.semantic_sha256
    ):
        raise ValueError("EXACT_DISABLED_SYNTHETIC_INITIAL_SELECTION_REQUIRED")
    plan = owners.owners.prepare_owner_command_read(
        previous=previous, original_receipt=request, fence=lease.fence
    )
    owners.owners.require_plan(plan)
    if (
        plan.dependencies.record != dependencies.record
        or plan.dependencies.reference != dependencies.reference
    ):
        raise ValueError("ORIGINAL_SYNTHETIC_SELECTION_REQUEST_DIFFERS")
    current = owners.daily.resolve_snapshot(
        owners.daily.read_snapshot(
            account_id=genesis.scope.account_id,
            fence=lease.fence,
            owner_command_ref=request,
        )
    )
    prepared = owners.daily.prepare_assignment(
        current,
        assignment=proposed,
        expected_previous_sha256=None,
        owner_command_ref=request,
    )
    _require_owners(genesis, owners, lease)
    return SqlRuntimeAssignmentPublication(account=owners.account, daily=owners.daily).publish(
        prepared, fence=lease.fence
    )
