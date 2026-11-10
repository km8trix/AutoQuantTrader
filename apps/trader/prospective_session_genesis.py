"""Initialize only a fresh disposable synthetic account with advancing local UTC.

The caller owns genuinely migrated, private, exclusive temporary stores. Retained
warmup is authenticated data, not permission to adopt an existing account. Actual
local samples do not establish measured clock health or provider qualification.
The original financial owners publish HALTED genesis and release the startup
fence; partial facts remain on failure. No assignment, rearm, retry or renewal.
"""

from __future__ import annotations

import time
from dataclasses import replace
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import sqlalchemy as sa

from apps.trader.prospective_session_capture import (
    ProspectiveSyntheticWarmupRetention,
    _require_plan,
)
from apps.trader.synthetic_session_capture import SyntheticBootstrapCapture, _prepare_scenarios
from apps.trader.synthetic_session_genesis import (
    SyntheticSessionGenesis,
    _publish_synthetic_genesis_under_lease,
    _require_fresh_capture_stores,
    _require_profile,
    _synthetic_genesis_values,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.adapters.synthetic_forward_capture import SyntheticForwardCaptureVerifier
from packages.application import personal_codec as codec
from packages.application.continuous_source_events import compile_continuous_bootstrap
from packages.domain.account_coordinator import AccountLeasePolicy
from packages.domain.clock import SystemClock
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
from packages.domain.forward_capture_contracts import CapturePublication
from packages.domain.forward_contracts import ForwardDataState
from packages.domain.identifiers import canonical_id
from packages.domain.personal_contracts import (
    VersionPin,
    content_digest,
    require_digest,
    require_utc,
)
from packages.domain.research_dataset import modeled_daily_availability
from packages.domain.research_job_contracts import require_identifier
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.continuous_forward_sources import SqlContinuousForwardSources


def _require_retention(retention: ProspectiveSyntheticWarmupRetention) -> tuple[str, ...]:
    """Check the declared two-capture profile, without granting source ownership."""
    if type(retention) is not ProspectiveSyntheticWarmupRetention:
        raise ValueError("exact prospective warmup retention required")
    require_digest(retention.plan_sha256, "prospective retained plan")
    if _require_plan(retention.plan) != retention.plan_sha256:
        raise ValueError("prospective retained plan differs")
    if type(retention.publications) is not tuple or len(retention.publications) != 2:
        raise ValueError("prospective initialization requires exactly two captures")
    for publication in retention.publications:
        if type(publication) is not CapturePublication:
            raise ValueError("original prospective capture publications required")
        publication.__post_init__()
        record = publication.record
        record.request.__post_init__()
        record.receipt.__post_init__()
        record.raw_object.__post_init__()
        record.__post_init__()
        publication.journal_receipt.__post_init__()

    first = retention.publications[0].record
    scenarios = _prepare_scenarios(retention.plan, first.request.calendar, first.request.producer)
    if first.request.window_start < max(
        event.knowledge_at for event in retention.plan.inputs.bootstrap_events
    ):
        raise ValueError("prospective capture preceded complete warmup availability")
    previous = None
    for publication, scenario in zip(retention.publications, scenarios, strict=True):
        record = publication.record
        request, receipt = record.request, record.receipt
        if (
            request
            != replace(
                scenario.request,
                capture_id=request.capture_id,
                window_start=request.window_start,
                window_end=request.window_end,
            )
            or request.window_end - request.window_start != timedelta(seconds=3)
            or request.deadline_ms != 3000
            or request.window_start < modeled_daily_availability(request.session)
            or receipt.requested_at < modeled_daily_availability(request.session)
            or record.raw_object.byte_count != len(scenario.body)
            or record.raw_object.object_sha256 != sha256(scenario.body).hexdigest()
            or receipt.boot_id != first.receipt.boot_id
        ):
            raise ValueError("prospective capture request, body or acquisition profile differs")
        if previous is not None and (
            request.window_start < previous.validated_at
            or receipt.requested_monotonic_ns < previous.validated_monotonic_ns
        ):
            raise ValueError("prospective capture stages regressed")
        verifier = SyntheticForwardCaptureVerifier(
            request, producer=request.producer, valid_until=request.window_end
        )
        for proof in record.verifications:
            proof.__post_init__()
            if verifier.verify(request, proof.sample) != proof:
                raise ValueError("prospective capture verification profile differs")
        previous = receipt

    sources = {scenario.request.source.source_id: scenario.request.source for scenario in scenarios}
    initial = ForwardDataState(tuple(sources[key] for key in sorted(sources)), "recorded")
    if (
        type(retention.initial_state) is not ForwardDataState
        or type(retention.state) is not ForwardDataState
        or retention.initial_state != initial
        or retention.state.sources != initial.sources
        or retention.state.mode != "recorded"
        or type(retention.state.observations) is not tuple
        or len(retention.state.observations) != 2
        or retention.state.frontiers != ()
    ):
        raise ValueError("prospective retained state profile differs")
    retention.initial_state.__post_init__()
    retention.state.__post_init__()
    selected = tuple(observation.observation_id for observation in retention.state.observations)
    if selected != tuple(
        sorted(
            observation.observation_id
            for publication in retention.publications
            for observation in publication.record.observations
        )
    ):
        raise ValueError("prospective retained observation inventory differs")
    return selected


def _source_closure(
    retention: ProspectiveSyntheticWarmupRetention,
    selected: tuple[str, ...],
    admitted_at: datetime,
    *,
    namespace: str,
) -> ContinuousForwardClosure:
    return ContinuousForwardClosure(
        account_id=retention.plan.inputs.spec.account_id,
        closure_id=canonical_id(
            namespace,
            retention.plan_sha256,
            admitted_at,
            tuple(publication.semantic_sha256 for publication in retention.publications),
            selected,
        ),
        initial_state=retention.initial_state,
        publications=retention.publications,
        observation_ids=selected,
        admitted_at=admitted_at,
        evidence_class="synthetic_fixture",
    )


def initialize_prospective_synthetic_session(
    retention: ProspectiveSyntheticWarmupRetention,
    *,
    account_engine: sa.Engine,
    venue_engine: sa.Engine,
    account_artifacts: LocalResearchArtifactStore,
    venue_artifacts: LocalResearchArtifactStore,
    owner_id: str,
    venue_pin: VersionPin,
    quote_producer: VersionPin,
) -> SyntheticSessionGenesis:
    """Authenticate retained warmup and publish one NEW actual-time HALTED C1.

    Private permissions/exclusive disposable ownership are caller preconditions;
    the original freshness guard checks its named paths and inventories. Admission
    is before the first scored close at the sampled initialization instant, not a
    promise that physical COMMIT finishes before that close. The clock keeps
    advancing for all original control, restore, fence, deadline and release checks.
    """
    selected = _require_retention(retention)
    require_identifier(owner_id, "synthetic startup owner")
    for pin in (venue_pin, quote_producer):
        if type(pin) is not VersionPin:
            raise ValueError("exact synthetic producer pins required")
        pin.__post_init__()
    if (
        type(account_engine) is not sa.Engine
        or type(venue_engine) is not sa.Engine
        or account_engine.dialect.name != "sqlite"
        or venue_engine.dialect.name != "sqlite"
        or type(account_artifacts) is not LocalResearchArtifactStore
        or type(venue_artifacts) is not LocalResearchArtifactStore
    ):
        raise ValueError("original temporary SQLite and local artifact owners required")
    fingerprint = content_digest(retention)
    clock = SystemClock()
    checked_at = clock.now()
    require_utc(checked_at, "prospective source check UTC")
    source_check = _source_closure(
        retention, selected, checked_at, namespace="prospective-synthetic-source-check/1"
    )
    forward = SqlContinuousForwardSources(
        account_engine, artifacts=account_artifacts, codec=codec, evidence_class="synthetic_fixture"
    )
    if forward.resolve(source_check).state != retention.state:
        raise ValueError("prospective retained captures differ from original source replay")
    _require_fresh_capture_stores(
        retention.publications, account_engine, venue_engine, account_artifacts, venue_artifacts
    )
    if content_digest(retention) != fingerprint:
        raise ValueError("prospective retention changed during admission")
    coordinator = SqlAccountCoordinator(
        account_id=retention.plan.inputs.spec.account_id,
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
        initialized_at = clock.now()
        require_utc(initialized_at, "prospective initialization UTC")
        if initialized_at < max(checked_at, lease.acquired_at):
            raise ValueError("prospective initialization clock regressed")
        spec = replace(retention.plan.inputs.spec, initialized_at=initialized_at)
        closure = _source_closure(
            retention,
            selected,
            initialized_at,
            namespace="prospective-synthetic-initialization/1",
        )
        resolved = forward.resolve(closure)
        if resolved.state != retention.state or content_digest(retention) != fingerprint:
            raise ValueError("prospective retained source changed before initialization")
        inputs = compile_continuous_bootstrap(
            spec,
            resolved.state,
            selected,
            initialized_at,
            benchmark_instrument_id="US-ETF-SPY",
            capture_evidence_class="synthetic_fixture",
        )
        bootstrap = SyntheticBootstrapCapture(inputs, closure, resolved.state)
        _require_profile(bootstrap)
        spec = inputs.spec
        seed, model, scope = _synthetic_genesis_values(spec, venue_pin)
        account, daily, runtime, owners, venue, control, restored, inventory = (
            _publish_synthetic_genesis_under_lease(
                bootstrap,
                spec=spec,
                benchmark="US-ETF-SPY",
                daily_request=retention.publications[0].record.request,
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
                monotonic_now_ns=time.monotonic_ns,
                epoch_id="prospective-synthetic-init-" + uuid4().hex,
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
