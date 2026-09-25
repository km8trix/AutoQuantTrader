"""Synthetic contract examples exercise both recorded and modeled normalization."""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.application.causal_engine import advance_continuous_engine
from packages.application.continuous_source_events import (
    forward_event_id,
    project_continuous_daily_frontier,
)
from packages.application.personal_codec import decode_record, encode_record
from packages.application.reference_strategy import ReferenceStrategy
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.engine_contracts import DailyPrice
from packages.domain.forward_contracts import (
    CaptureReceipt,
    ForwardDataState,
    ForwardObservation,
    ForwardSource,
    ModeledAvailability,
)
from packages.domain.personal_contracts import content_digest
from tests.unit.test_continuous_engine import (
    FixtureEvidence,
    economic_values,
    inputs_and_prices,
    start,
)


def setup(recorded=True):
    inputs, prices = inputs_and_prices()
    if recorded:
        bootstrap = tuple(
            replace(
                event,
                provenance=replace(
                    event.provenance,
                    data_class="recorded_as_observed",
                    observed_at=event.knowledge_at,
                    simulated_available_at=None,
                    assumption_id=None,
                    raw_sha256="a" * 64,
                ),
            )
            for event in inputs.bootstrap_events
        )
        inputs = replace(
            inputs,
            spec=replace(
                inputs.spec,
                source_mode="recorded_as_observed",
                bootstrap_events_sha256=content_digest(bootstrap),
            ),
            bootstrap_events=bootstrap,
        )
    source = ForwardSource(
        "unit-capture",
        "tiingo" if recorded else "fixture",
        "production" if recorded else "synthetic",
        None,
        "synthetic-identity-proof",
        "allowed",
        "synthetic-rights-proof",
        "not_required",
        "synthetic-entitlement-proof",
    )
    observations = []
    for index, event in enumerate(prices):
        at = event.knowledge_at
        availability = (
            CaptureReceipt(
                f"unit-capture-{index}",
                source.semantic_sha256,
                "b" * 64,
                "c" * 64,
                120,
                at - timedelta(milliseconds=20),
                at,
                at + timedelta(milliseconds=20),
                "synthetic-boot",
                index * 1000000000,
                index * 1000000000 + 20000000,
                index * 1000000000 + 40000000,
            )
            if recorded
            else (ModeledAvailability(at, "unit-fixture-availability"))
        )
        observations.append(
            ForwardObservation(
                f"observation-{index}",
                source.source_id,
                event.payload,
                availability,
                f"daily-{index}",
            )
        )
    state = ForwardDataState((source,), "recorded" if recorded else "modeled", tuple(observations))
    return start(inputs), state


def project(checkpoint, state, selected=None, at=None, identity="fixture-frontier"):
    selected = selected or (state.observations[0].observation_id,)
    at = at or max(
        value.known_at for value in state.observations if value.observation_id in selected
    ) + timedelta(milliseconds=10)
    return project_continuous_daily_frontier(
        checkpoint=checkpoint,
        source_state=state,
        observation_ids=tuple(sorted(selected)),
        frontier_id=identity,
        admitted_at=at,
        benchmark_instrument_id=checkpoint.inputs.spec.instruments[0][0],
    )


def advance(checkpoint, frontier):
    return advance_continuous_engine(
        checkpoint,
        frontier,
        expected_sha256=checkpoint.semantic_sha256,
        accounting=PersonalAccounting(),
        strategy=ReferenceStrategy(),
        runtime_evidence=FixtureEvidence(checkpoint.inputs.spec),
    )


@pytest.mark.parametrize("recorded", [True, False])
def test_forward_prices_keep_original_availability_and_replay_identical_decisions(recorded):
    checkpoint, state = setup(recorded)
    continuous = restarted = checkpoint
    for observation in state.observations:
        frontier = project(
            continuous, state, (observation.observation_id,), identity=observation.observation_id
        )
        other = project(
            restarted, state, (observation.observation_id,), identity=observation.observation_id
        )
        continuous, restarted = advance(continuous, frontier), advance(restarted, other)
        restarted = decode_record(encode_record(restarted), CausalEngineCheckpoint)
        assert economic_values(continuous) == economic_values(restarted)
        price = next(event for event in frontier.events if isinstance(event.payload, DailyPrice))
        assert price.knowledge_at == frontier.knowledge_at
        assert price.provenance.observed_at == (observation.known_at if recorded else None)
        assert price.source_sequence is None and price.provenance.vendor_published_at is None
    assert continuous.runtime_decisions and any(
        d.disposition == "installed" for d in continuous.runtime_decisions
    )


def test_duplicate_retains_original_event_and_never_changes_knowledge_time():
    checkpoint, state = setup()
    first = project(checkpoint, state)
    after = advance(checkpoint, first)
    duplicate = project(after, state, at=after.now + timedelta(seconds=1), identity="duplicate")
    assert duplicate.events == first.events
    later = advance(after, duplicate)
    assert later.runtime_decisions == after.runtime_decisions


def test_late_worker_never_backdates_a_daily_decision():
    checkpoint, state = setup()
    observation = state.observations[0]
    session = next(
        s
        for s in checkpoint.inputs.spec.calendar.sessions
        if s.session_label > observation.payload.session
    )
    frontier = project(checkpoint, state, at=session.opens_at + timedelta(minutes=31))
    assert all(event.knowledge_at == frontier.knowledge_at for event in frontier.events)
    result = advance(checkpoint, frontier)
    assert not result.runtime_decisions


def test_revision_requires_actual_parent_and_keeps_original_raw_receipts():
    checkpoint, state = setup()
    original = state.observations[0]
    corrected = replace(
        original, observation_id="revision-2", revision=2, predecessor_id=original.observation_id
    )
    state = replace(state, observations=(*state.observations, corrected))
    with pytest.raises(ValueError, match="skip an unadmitted parent"):
        project(checkpoint, state, (corrected.observation_id,))
    first = project(checkpoint, state)
    after = advance(checkpoint, first)
    frontier = project(
        after,
        state,
        (corrected.observation_id,),
        at=after.now + timedelta(seconds=1),
        identity="revision-frontier",
    )
    value = next(event for event in frontier.events if isinstance(event.payload, DailyPrice))
    assert value.payload.predecessor_revision_id == forward_event_id(original.observation_id)
    assert value.predecessor_ids == (forward_event_id(original.observation_id),)
    assert value.provenance.observed_at == original.known_at
    advance(after, frontier)


@pytest.mark.parametrize("change", ["future", "unknown", "mode", "sequence"])
def test_missing_future_or_unqualified_source_shapes_are_explicitly_rejected(change):
    checkpoint, state = setup()
    observation = state.observations[0]
    kwargs = {}
    if change == "future":
        kwargs["at"] = observation.known_at - timedelta(microseconds=1)
    elif change == "unknown":
        kwargs["selected"] = ("missing",)
        kwargs["at"] = observation.known_at
    elif change == "mode":
        _, state = setup(False)
    else:
        source = replace(
            state.sources[0],
            sequence_scope="actual-scope",
            sequence_start=1,
            sequence_reference="sequence-proof",
        )
        observation = replace(
            observation,
            source_sequence=1,
            availability=replace(observation.availability, source_sha256=source.semantic_sha256),
        )
        state = replace(state, sources=(source,), observations=(observation,))
    with pytest.raises(ValueError):
        project(checkpoint, state, **kwargs)


@pytest.mark.parametrize("field", ["identity_reference", "rights_reference"])
def test_pending_source_qualification_cannot_be_normalized(field):
    checkpoint, state = setup()
    source = replace(state.sources[0], **{field: None})
    observation = state.observations[0]
    observation = replace(
        observation,
        availability=replace(observation.availability, source_sha256=source.semantic_sha256),
    )
    state = replace(state, sources=(source,), observations=(observation,))
    with pytest.raises(ValueError, match="declared rights"):
        project(checkpoint, state)


def test_benchmark_cannot_start_with_an_unemitted_revision_parent():
    checkpoint, state = setup()
    original = state.observations[0]
    first = project_continuous_daily_frontier(
        checkpoint=checkpoint,
        source_state=state,
        observation_ids=(original.observation_id,),
        frontier_id="daily-only",
        admitted_at=original.known_at + timedelta(milliseconds=10),
    )
    checkpoint = advance(checkpoint, first)
    corrected = replace(
        original, observation_id="revision-2", revision=2, predecessor_id=original.observation_id
    )
    state = replace(state, observations=(*state.observations, corrected))
    with pytest.raises(ValueError, match="benchmark parent"):
        project(
            checkpoint, state, (corrected.observation_id,), at=checkpoint.now + timedelta(seconds=1)
        )


def bootstrap_case(recorded=True):
    inputs, _ = inputs_and_prices()
    _, template = setup(recorded)
    source = template.sources[0]
    observations = []
    for index, event in enumerate(inputs.bootstrap_events):
        at = event.knowledge_at
        availability = (
            CaptureReceipt(
                f"bootstrap-capture-{index}",
                source.semantic_sha256,
                "b" * 64,
                "c" * 64,
                120,
                at - timedelta(milliseconds=20),
                at,
                at + timedelta(milliseconds=20),
                "synthetic-boot",
                index * 1000000000,
                index * 1000000000 + 20000000,
                index * 1000000000 + 40000000,
            )
            if recorded
            else ModeledAvailability(at, "unit-fixture-availability")
        )
        observations.append(
            ForwardObservation(
                f"bootstrap-observation-{index}",
                source.source_id,
                event.payload,
                availability,
                f"bootstrap-daily-{index}",
            )
        )
    state = replace(template, observations=tuple(observations))
    spec = replace(
        inputs.spec, source_mode=("recorded_as_observed" if recorded else "synthetic_observed")
    )
    return spec, state, tuple(sorted(o.observation_id for o in observations))


@pytest.mark.parametrize("recorded", [True, False])
def test_bootstrap_reuses_forward_normalizer_and_replays_exact_initialization(recorded):
    from packages.application.continuous_source_events import compile_continuous_bootstrap

    spec, state, selected = bootstrap_case(recorded)
    inputs = compile_continuous_bootstrap(
        spec,
        state,
        selected,
        spec.initialized_at,
        benchmark_instrument_id=spec.instruments[0][0],
    )
    assert replace(inputs.spec, bootstrap_events_sha256=spec.bootstrap_events_sha256) == spec
    assert inputs.spec.bootstrap_events_sha256 == content_digest(inputs.bootstrap_events)
    checkpoint = start(inputs)
    assert not checkpoint.runtime_decisions
    assert checkpoint.inputs == inputs
    repeated = compile_continuous_bootstrap(
        decode_record(encode_record(inputs.spec), type(spec)),
        decode_record(encode_record(state), type(state)),
        selected,
        spec.initialized_at,
        benchmark_instrument_id=spec.instruments[0][0],
    )
    assert repeated == inputs
    assert economic_values(start(repeated)) == economic_values(checkpoint)
    for observation in state.observations:
        event = next(
            e
            for e in inputs.bootstrap_events
            if e.event_id == forward_event_id(observation.observation_id)
        )
        assert event.knowledge_at == spec.initialized_at
        assert event.provenance.observed_at == (observation.known_at if recorded else None)
        assert event.provenance.simulated_available_at == (
            None if recorded else observation.known_at
        )
    # An already normalized duplicate remains exactly the original event, even
    # when an ordinary later frontier passes through the same normalizer.
    frontier = project_continuous_daily_frontier(
        checkpoint=checkpoint,
        source_state=state,
        observation_ids=selected,
        frontier_id="bootstrap-duplicate",
        admitted_at=checkpoint.now + timedelta(seconds=1),
        benchmark_instrument_id=spec.instruments[0][0],
    )
    assert frontier.events == inputs.bootstrap_events


@pytest.mark.parametrize("change", ["missing", "outside", "future", "boundary", "mode"])
def test_bootstrap_rejects_incomplete_warmup_and_rewritten_knowledge(change):
    from packages.application.continuous_source_events import compile_continuous_bootstrap

    spec, state, selected = bootstrap_case()
    at = spec.initialized_at
    if change == "missing":
        selected = selected[:-1]
    elif change == "outside":
        _, prices = inputs_and_prices()
        original = state.observations[0]
        state = replace(
            state,
            observations=(
                replace(original, payload=prices[0].payload),
                *state.observations[1:],
            ),
        )
    elif change == "future":
        original = state.observations[0]
        receipt = original.availability
        delta = at - receipt.validated_at + timedelta(seconds=1)
        state = replace(
            state,
            observations=(
                replace(
                    original,
                    availability=replace(
                        receipt,
                        requested_at=receipt.requested_at + delta,
                        received_at=receipt.received_at + delta,
                        validated_at=receipt.validated_at + delta,
                    ),
                ),
                *state.observations[1:],
            ),
        )
    elif change == "boundary":
        at += timedelta(seconds=1)
    else:
        spec = replace(spec, source_mode="synthetic_observed")
    with pytest.raises(ValueError):
        compile_continuous_bootstrap(spec, state, selected, at)


@pytest.mark.parametrize("recorded", [True, False])
def test_declared_zero_warmup_compiles_empty_start_without_weakening_frontier_selection(recorded):
    from packages.application.continuous_source_events import compile_continuous_bootstrap

    spec, state, _ = bootstrap_case(recorded)
    spec = replace(spec, window=replace(spec.window, warmup_sessions=()))
    inputs = compile_continuous_bootstrap(spec, state, (), spec.initialized_at)
    assert inputs.bootstrap_events == ()
    assert inputs.spec.bootstrap_events_sha256 == content_digest(())
    checkpoint = start(inputs)
    assert not checkpoint.runtime_decisions
    with pytest.raises(ValueError, match="bounded unique selection"):
        project_continuous_daily_frontier(
            checkpoint=checkpoint,
            source_state=state,
            observation_ids=(),
            frontier_id="empty-daily",
            admitted_at=checkpoint.now + timedelta(seconds=1),
        )
    with pytest.raises(ValueError, match="interchanged"):
        compile_continuous_bootstrap(
            replace(
                spec, source_mode=("synthetic_observed" if recorded else "recorded_as_observed")
            ),
            state,
            (),
            spec.initialized_at,
        )
