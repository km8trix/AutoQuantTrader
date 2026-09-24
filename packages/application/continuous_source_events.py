"""Project retained forward daily observations into the single causal engine.

This pure normalization does not authenticate storage, rights or source clocks.
The runtime resolves a fixed-through captured source closure before calling it.
Actual capture timestamps remain provenance; the coordinator's original closure
is the knowledge boundary used again on replay, including late wakeups.
"""

from dataclasses import replace
from datetime import datetime

from packages.domain.accounting_contracts import AccountingState
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import (
    ClosedEngineFrontier,
    ContinuousEngineInputs,
    ContinuousEngineSpec,
)
from packages.domain.engine_contracts import (
    BenchmarkPrice,
    DailyPrice,
    EngineEvent,
    ObservationProvenance,
)
from packages.domain.forward_capture_contracts import CaptureEvidenceClass
from packages.domain.forward_contracts import CaptureReceipt, ForwardDataState, ModeledAvailability
from packages.domain.personal_contracts import content_digest, require_utc
from packages.domain.research_dataset import ResearchDataClass

NORMALIZER_VERSION = "personal-continuous-forward-daily/1"
MAX_SELECTED_OBSERVATIONS = 2048


def forward_event_id(observation_id: str, *, benchmark: bool = False) -> str:
    return content_digest(
        (NORMALIZER_VERSION, "benchmark" if benchmark else "daily", observation_id)
    )


def project_continuous_daily_frontier(
    *,
    checkpoint: CausalEngineCheckpoint,
    source_state: ForwardDataState,
    observation_ids: tuple[str, ...],
    frontier_id: str,
    admitted_at: datetime,
    benchmark_instrument_id: str | None = None,
    capture_evidence_class: CaptureEvidenceClass | None = None,
) -> ClosedEngineFrontier:
    """Normalize exact selected IDs without historical next-open/availability models.

    Unseen revision parents, unsupported sequenced sources, future receipt times,
    unknown sessions, mismatched raw sources and quote inputs fail explicitly.
    Duplicate observations reuse the original event and its knowledge time.
    """
    require_utc(admitted_at, "continuous source admission")
    if type(checkpoint.inputs) is not ContinuousEngineInputs:
        raise ValueError("forward normalization requires a continuous checkpoint")
    if admitted_at <= checkpoint.now:
        raise ValueError("forward admission requires a later bounded unique selection")
    events, closure = _normalize_daily_events(
        spec=checkpoint.inputs.spec,
        source_state=source_state,
        observation_ids=observation_ids,
        admitted_at=admitted_at,
        previous_events=checkpoint.events,
        benchmark_instrument_id=benchmark_instrument_id,
        capture_evidence_class=capture_evidence_class,
    )
    return ClosedEngineFrontier(
        frontier_id=frontier_id,
        stream_id=checkpoint.inputs.spec.run_id,
        previous_checkpoint_sha256=checkpoint.semantic_sha256,
        source_frontier_sha256=closure,
        knowledge_at=admitted_at,
        events=events,
    )


def compile_continuous_bootstrap(
    spec: ContinuousEngineSpec,
    source_state: ForwardDataState,
    observation_ids: tuple[str, ...],
    admitted_at: datetime,
    *,
    benchmark_instrument_id: str | None = None,
    capture_evidence_class: CaptureEvidenceClass | None = None,
) -> ContinuousEngineInputs:
    """Compile complete retained warmup through the same forward normalizer.

    Only the derived bootstrap digest is replaced on the supplied specification.
    Original capture availability remains provenance; initialization is the exact
    coordinator knowledge boundary. Storage/source authentication is the caller's
    responsibility, just as for ordinary frontiers.
    """
    require_utc(admitted_at, "continuous bootstrap admission")
    if admitted_at != spec.initialized_at:
        raise ValueError("bootstrap admission must equal the declared initialization")
    events, _ = _normalize_daily_events(
        spec=spec,
        source_state=source_state,
        observation_ids=observation_ids,
        admitted_at=admitted_at,
        previous_events=(),
        benchmark_instrument_id=benchmark_instrument_id,
        capture_evidence_class=capture_evidence_class,
        allow_empty=not spec.window.warmup_sessions,
    )
    actual = {
        (event.payload.instrument_id, event.payload.session)
        for event in events
        if type(event.payload) is DailyPrice
    }
    expected = {
        (instrument_id, session)
        for instrument_id, _ in spec.instruments
        for session in spec.window.warmup_sessions
    }
    if actual != expected:
        raise ValueError("bootstrap requires exactly the declared complete warmup coverage")
    return ContinuousEngineInputs(
        spec=replace(spec, bootstrap_events_sha256=content_digest(events)),
        initial_state=AccountingState(spec.account_id),
        bootstrap_events=events,
    )


def _normalize_daily_events(
    *,
    spec: ContinuousEngineSpec,
    source_state: ForwardDataState,
    observation_ids: tuple[str, ...],
    admitted_at: datetime,
    previous_events: tuple[EngineEvent, ...],
    benchmark_instrument_id: str | None,
    capture_evidence_class: CaptureEvidenceClass | None,
    allow_empty: bool = False,
) -> tuple[tuple[EngineEvent, ...], str]:
    require_utc(admitted_at, "continuous source admission")
    if (
        type(observation_ids) is not tuple
        or observation_ids != tuple(sorted(set(observation_ids)))
        or not (0 if allow_empty else 1) <= len(observation_ids) <= MAX_SELECTED_OBSERVATIONS
    ):
        raise ValueError("forward admission requires a later bounded unique selection")
    recorded = spec.source_mode == "recorded_as_observed"
    if capture_evidence_class is not None:
        if capture_evidence_class not in ("synthetic_fixture", "provider_https_read"):
            raise ValueError("explicit capture evidence class is unsupported")
        if recorded != (capture_evidence_class == "provider_https_read"):
            raise ValueError("continuous daily capture source class cannot be promoted")
        if source_state.mode != "recorded":
            raise ValueError("explicit capture class requires original captured source state")
    elif (source_state.mode == "recorded") != recorded:
        raise ValueError("recorded and synthetic forward modes cannot be interchanged")
    instruments = dict(spec.instruments)
    if benchmark_instrument_id is not None and (instruments.get(benchmark_instrument_id) != "SPY"):
        raise ValueError("forward benchmark requires the explicitly selected SPY identity")
    sources = {source.source_id: source for source in source_state.sources}
    observations = {value.observation_id: value for value in source_state.observations}
    previous = {event.event_id: event for event in previous_events}
    sessions = {session.session_label: session for session in spec.calendar.sessions}
    events: list[EngineEvent] = []
    selected = []
    for identifier in observation_ids:
        observation = observations.get(identifier)
        if observation is None or type(observation.payload) is not DailyPrice:
            raise ValueError("forward daily selection is missing or contains a quote")
        source = sources.get(observation.source_id)
        if source is None or (
            source.rights_status != "allowed"
            or source.identity_reference is None
            or source.rights_reference is None
        ):
            raise ValueError("forward source identity or declared rights are unavailable")
        if observation.source_sequence is not None or source.sequence_scope is not None:
            raise ValueError("sequenced sources require an explicit normalization order bridge")
        if observation.known_at > admitted_at:
            raise ValueError("forward observation is not yet known at this closure")
        payload = observation.payload
        if (
            instruments.get(payload.instrument_id) != payload.symbol
            or payload.session not in sessions
        ):
            raise ValueError("forward instrument or session differs from the frozen stream")
        close = sessions[payload.session].closes_at
        if observation.known_at < close:
            raise ValueError("complete daily observation cannot precede its session close")
        parent = observation.predecessor_id
        if parent is not None:
            ancestor = observations.get(parent)
            if ancestor is None or (
                ancestor.source_id != observation.source_id
                or ancestor.revision_key != observation.revision_key
                or ancestor.revision + 1 != observation.revision
                or ancestor.known_at > observation.known_at
                or not isinstance(ancestor.payload, DailyPrice)
                or (ancestor.payload.instrument_id, ancestor.payload.session)
                != (payload.instrument_id, payload.session)
            ):
                raise ValueError("forward daily revision ancestry is incomplete or mismatched")
            if parent not in observation_ids and forward_event_id(parent) not in previous:
                raise ValueError("forward revision cannot skip an unadmitted parent")
        availability = observation.availability
        if recorded or capture_evidence_class is not None:
            if type(availability) is not CaptureReceipt or (
                availability.source_sha256 != source.semantic_sha256
                or (recorded and source.provider == "fixture")
                or (recorded and source.environment == "synthetic")
            ):
                raise ValueError("captured forward event requires its exact source receipt")
            raw = availability.raw_sha256
            actual, modeled, assumption = (
                (observation.known_at, None, None)
                if recorded
                else (None, availability.validated_at, "synthetic-capture-replay/1")
            )
        else:
            if type(availability) is not ModeledAvailability or source.provider != "fixture":
                raise ValueError("synthetic forward event requires explicit modeled availability")
            raw = None
            actual, modeled, assumption = (
                None,
                availability.available_at,
                availability.assumption_id,
            )
        normalized = replace(
            payload,
            revision=observation.revision,
            predecessor_revision_id=None if parent is None else forward_event_id(parent),
        )
        emitted: list[tuple[DailyPrice | BenchmarkPrice, bool]] = [(normalized, False)]
        if payload.instrument_id == benchmark_instrument_id:
            if (
                parent is not None
                and parent not in observation_ids
                and (forward_event_id(parent, benchmark=True) not in previous)
            ):
                raise ValueError("forward benchmark revision has no admitted benchmark parent")
            emitted.append(
                (
                    BenchmarkPrice(
                        "SPY-total-return-units/1",
                        payload.adjusted_close,
                        "adjusted_total_return_units"
                        if recorded
                        else "synthetic_total_return_units",
                    ),
                    True,
                )
            )
        for value, benchmark in emitted:
            event = EngineEvent(
                event_id=forward_event_id(identifier, benchmark=benchmark),
                economic_at=close,
                knowledge_at=admitted_at,
                payload=value,
                provenance=ObservationProvenance(
                    data_class="recorded_as_observed"
                    if recorded
                    else ResearchDataClass.SYNTHETIC_FIXTURE,
                    source_namespace=source.source_id,
                    normalized_sha256=content_digest(value),
                    observed_at=actual,
                    simulated_available_at=modeled,
                    assumption_id=assumption,
                    raw_sha256=raw,
                    limitations=(NORMALIZER_VERSION,)
                    + (
                        ("synthetic capture does not qualify provider access",)
                        if capture_evidence_class == "synthetic_fixture"
                        else ()
                    ),
                ),
                predecessor_ids=()
                if parent is None
                else (forward_event_id(parent, benchmark=benchmark),),
            )
            old = previous.get(event.event_id)
            if old is not None:
                if replace(event, knowledge_at=old.knowledge_at) != old:
                    raise ValueError("retained normalized observation conflicts with its source")
                event = old
            events.append(event)
        selected.append((observation.semantic_sha256, source.semantic_sha256))
    original_closure = (NORMALIZER_VERSION, tuple(selected), admitted_at, benchmark_instrument_id)
    closure = content_digest(
        original_closure
        if capture_evidence_class is None
        else (*original_closure, capture_evidence_class)
    )
    return tuple(sorted(events, key=lambda event: event.event_id)), closure
