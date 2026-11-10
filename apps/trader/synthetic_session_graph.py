"""Wire a synthetic session around caller-owned, already initialized stores.

This constructor creates no engines, schemas or object roots, acquires no lease,
and does not initialize a venue, install an assignment or re-arm controls. Its
supplied runtime must already refer to the caller's original current fence and
explicit modeled clock.
It leaves the retained HALTED restore factory and its authentication untouched.
"""

from collections.abc import Callable
from datetime import datetime
from threading import Event

from sqlalchemy import Engine

from apps.trader.continuous_session import ContinuousSessionCoordinator, ContinuousSessionStopped
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.adapters.runtime_clock_evidence import RuntimeClockSampler
from packages.domain.account_coordinator import AccountFence
from packages.domain.operational_control import OperationalControlState
from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.domain.research_job_contracts import ResearchRecordCodec
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.continuous_attempt_outcome_sources import (
    SqlContinuousAttemptOutcomeSources,
)
from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_observed_hold_sources import SqlContinuousObservedHoldSources
from packages.persistence.continuous_reconciliation_publication import (
    SqlContinuousReconciliationPublication,
)
from packages.persistence.continuous_runtime_attempt_sources import (
    SqlContinuousRuntimeAttemptSources,
)
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.continuous_simulation_delivery import SqlContinuousSimulationDelivery
from packages.persistence.continuous_venue_sources import SqlContinuousVenueSources
from packages.persistence.daily_runtime_risk import SqlDailyRuntimeRisk
from packages.persistence.stateful_venue import SqlStatefulVenue
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture


def build_synthetic_session_graph(
    *,
    account: SqlContinuousAccount,
    runtime: SqlContinuousRuntimeSources,
    daily: SqlDailyRuntimeRisk,
    venue_sources: SqlContinuousVenueSources,
    venue_engine: Engine,
    venue_artifacts: LocalResearchArtifactStore,
    codec: ResearchRecordCodec,
    capture_clock: Callable[[], datetime],
    stop_event: Event,
) -> ContinuousSessionCoordinator:
    """Bind original concrete owners without granting simulation authority.

    The account must already contain synthetic genesis and remain HALTED. The
    independent venue and both private object stores must already exist. Existing
    delivery checks authenticate distinct physical SQLite/object-store identities;
    a different Engine object or URL alone does not establish independence.

    ``capture_clock`` is the caller's declared synthetic UTC model, used only by
    subsequent reconciliation. Construction does not sample or advance it. The
    runtime's standard sampler must separately declare its simulation profile.
    Caller-created stores are a precondition: a supplied SQLite Engine may itself
    create a missing file on first connect. Normal coordinator validation can
    maintain observation metadata; it cannot acquire or renew a lease here.
    """
    if (
        type(account) is not SqlContinuousAccount
        or type(runtime) is not SqlContinuousRuntimeSources
        or type(daily) is not SqlDailyRuntimeRisk
        or type(venue_sources) is not SqlContinuousVenueSources
        or not isinstance(venue_engine, Engine)
        or type(venue_artifacts) is not LocalResearchArtifactStore
        or type(stop_event) is not Event
        or not callable(capture_clock)
    ):
        raise ValueError("EXACT_SYNTHETIC_SESSION_PORTS_REQUIRED")
    if Event.is_set(stop_event):
        raise ContinuousSessionStopped("CONTINUOUS_SESSION_STOPPED")
    composer = account.composer
    publisher = runtime.publisher
    if (
        type(composer) is not SqlContinuousCommitComposer
        or type(publisher) is not SqlContinuousReconciliationPublication
        or account.engine is not runtime.engine
        or daily.engine is not account.engine
        or venue_sources.engine is not account.engine
        or runtime.accounts is not account
        or runtime.daily is not daily
        or daily.producers is not runtime
        or runtime.coordinator is not account.coordinator
        or daily.coordinator is not account.coordinator
        or composer.daily is not daily
        or composer.producer_history is not runtime
        or composer.venue_sources is not venue_sources
        or publisher.account is not account
        or publisher.composer is not composer
        or publisher.sources is not venue_sources
        or publisher.coordinator is not account.coordinator
        or account.preparer.runtime_evidence is not runtime
        or account.preparer.accounting is not runtime.accounting
        or publisher.accounting is not runtime.accounting
        or account.artifacts is not runtime.artifacts
        or publisher.artifacts is not account.artifacts
        or venue_sources.artifacts is not account.artifacts
        or type(account.artifacts) is not LocalResearchArtifactStore
        or any(
            item.codec is not codec for item in (account, runtime, daily, publisher, venue_sources)
        )
        or venue_sources.model is not runtime.venue_model
        or runtime.attempt_sources is not None
        or runtime.observed_hold_sources is not None
        or runtime._attempt_sources_binding is not None
        or runtime._observed_sources_binding is not None
        or runtime._observed_sources_pins is not None
    ):
        raise ValueError("ORIGINAL_UNBOUND_SYNTHETIC_SESSION_GRAPH_REQUIRED")
    sampler = runtime.operating.clock_sampler
    if type(sampler) is not RuntimeClockSampler:
        raise ValueError("LIVE_DISABLED_SYNTHETIC_SESSION_PROFILE_REQUIRED")
    model = runtime.venue_model
    scope = sampler.scope
    model.__post_init__()
    fence = runtime.current_fence()
    if type(fence) is not AccountFence:
        raise ValueError("ORIGINAL_SYNTHETIC_SESSION_FENCE_REQUIRED")
    fence.__post_init__()
    expected_scope = ReconciliationScope(
        model.account_id,
        model.venue_id,
        "stateful_simulation",
        scope.account_binding_sha256,
        "stateful_simulation",
    )
    if (
        sampler.profile != "explicit_simulation_time_model"
        or runtime.forward_sources.evidence_class != "synthetic_fixture"
        or model.source_mode != "synthetic_fixture"
        or model.live_authorized is not False
        or model.runtime_environment != "stateful_simulation"
        or scope.account_id != model.account_id
        or fence.account_id != scope.account_id
        or venue_sources.scope != expected_scope
    ):
        raise ValueError("LIVE_DISABLED_SYNTHETIC_SESSION_PROFILE_REQUIRED")
    # Authenticate current persisted inputs/control before changing owner bindings.
    restored = account.restore(scope)
    if restored is None:
        raise ValueError("SYNTHETIC_SESSION_EXISTING_GENESIS_REQUIRED")
    spec = restored.checkpoint.inputs.spec
    current = daily.resolve_snapshot(daily.read_snapshot(account_id=scope.account_id, fence=fence))
    if (
        spec.environment != "stateful_simulation"
        or spec.source_mode != "synthetic_observed"
        or spec.live_authorized is not False
        or current.control is None
        or current.control.effective_state is not OperationalControlState.HALTED
    ):
        raise ValueError("HALTED_SYNTHETIC_SESSION_GENESIS_REQUIRED")

    observed = SqlContinuousObservedHoldSources(
        account.engine,
        accounts=account,
        preparer=account.preparer,
        venue_sources=venue_sources,
        daily=daily,
        artifacts=account.artifacts,
        codec=codec,
    )
    attempts = SqlContinuousRuntimeAttemptSources(
        account.engine,
        accounts=account,
        preparer=account.preparer,
        daily=daily,
        runtime_sources=runtime,
        artifacts=account.artifacts,
        codec=codec,
    )
    attempt_publisher = SqlContinuousAttemptPublication(account=account)
    delivery = SqlContinuousSimulationDelivery(publisher=attempt_publisher, sources=attempts)
    venue = SqlStatefulVenue(
        venue_engine,
        model=model,
        artifacts=venue_artifacts,
        codec=codec,
        accounting=runtime.accounting,
        verified_sources=delivery,
    )
    # This original owner performs alias checks before either supplied runtime bind.
    delivery.bind_venue(venue)
    # Construction alone does not prove this independent store contains the
    # declared venue. Authenticate its retained genesis/model/state without
    # initializing or changing it, before mutating the caller's runtime graph.
    venue.read()
    outcomes = SqlContinuousAttemptOutcomeSources(
        attempts=attempts,
        venue=venue,
        capture=SqlVenueReconciliationCapture(
            account.engine, artifacts=account.artifacts, codec=codec, clock=capture_clock
        ),
        venue_sources=SqlContinuousVenueSources(
            account.engine,
            artifacts=account.artifacts,
            codec=codec,
            resolver=venue_sources.resolver,
            scope=ReconciliationScope(
                model.account_id,
                model.venue_id,
                "stateful_simulation",
                runtime.venue_reference.semantic_sha256_ref,
                "stateful_simulation",
            ),
            model=model,
        ),
    )
    attempts.bind_outcome_sources(outcomes)
    if Event.is_set(stop_event):
        raise ContinuousSessionStopped("CONTINUOUS_SESSION_STOPPED")
    runtime.bind_observed_hold_sources(observed)
    runtime.bind_attempt_sources(attempts)
    return ContinuousSessionCoordinator(
        account=account, delivery=delivery, outcomes=outcomes, stop_event=stop_event
    )
