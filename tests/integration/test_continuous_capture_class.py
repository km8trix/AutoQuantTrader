"""Capture-class normalization without provider access or trading qualification.

Provider-branch unit cases use explicitly constructed contract-shape fixtures.
The SQL cases retain actual fixture capture journals/bytes and remain synthetic.
"""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.application import personal_codec as codec
from packages.application.continuous_quote_frontier import project_continuous_quote_frontier
from packages.application.continuous_source_events import (
    NORMALIZER_VERSION,
    compile_continuous_bootstrap,
    forward_event_id,
    project_continuous_daily_frontier,
)
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
from packages.domain.engine_contracts import BenchmarkPrice
from packages.domain.forward_contracts import CaptureReceipt
from packages.domain.personal_contracts import content_digest
from packages.domain.research_dataset import ResearchDataClass
from packages.persistence.continuous_forward_sources import (
    ContinuousForwardSourceError,
    SqlContinuousForwardSources,
)
from tests.integration.test_continuous_composition import Case
from tests.integration.test_continuous_quote_frontier import case as quote_case  # noqa: F401
from tests.unit.test_continuous_engine import start
from tests.unit.test_continuous_source_events import bootstrap_case, project, setup


def captured_bootstrap(evidence_class):
    spec, state, selected = bootstrap_case(True)
    spec = replace(
        spec,
        source_mode="recorded_as_observed"
        if evidence_class == "provider_https_read"
        else "synthetic_observed",
    )
    inputs = compile_continuous_bootstrap(
        spec,
        state,
        selected,
        spec.initialized_at,
        benchmark_instrument_id=spec.instruments[0][0],
        capture_evidence_class=evidence_class,
    )
    return inputs, state, selected


@pytest.mark.parametrize("evidence_class", ["synthetic_fixture", "provider_https_read"])
def test_captured_bootstrap_and_frontier_preserve_original_receipt_time_and_hash(evidence_class):
    inputs, state, selected = captured_bootstrap(evidence_class)
    recorded = evidence_class == "provider_https_read"
    original = codec.encode_record(state)
    original_receipts = tuple(item.availability for item in state.observations)
    checkpoint = start(inputs)
    assert inputs.spec.source_mode == ("recorded_as_observed" if recorded else "synthetic_observed")
    for observation, receipt in zip(state.observations, original_receipts, strict=True):
        assert type(receipt) is CaptureReceipt
        for benchmark in (False, True):
            event = next(
                value
                for value in inputs.bootstrap_events
                if value.event_id
                == forward_event_id(observation.observation_id, benchmark=benchmark)
            )
            assert event.knowledge_at == inputs.spec.initialized_at
            assert event.provenance.raw_sha256 == receipt.raw_sha256
            assert event.provenance.source_namespace == observation.source_id
            assert event.provenance.normalized_sha256 == content_digest(event.payload)
            assert event.provenance.observed_at == (receipt.validated_at if recorded else None)
            assert event.provenance.simulated_available_at == (
                None if recorded else receipt.validated_at
            )
            assert event.provenance.assumption_id == (
                None if recorded else "synthetic-capture-replay/1"
            )
            assert event.provenance.data_class == (
                "recorded_as_observed" if recorded else ResearchDataClass.SYNTHETIC_FIXTURE
            )
            if not recorded:
                assert (
                    "synthetic capture does not qualify provider access"
                    in event.provenance.limitations
                )
            if isinstance(event.payload, BenchmarkPrice):
                assert event.payload.representation == (
                    "adjusted_total_return_units" if recorded else "synthetic_total_return_units"
                )
    admitted = checkpoint.now + timedelta(seconds=1)
    duplicate = project_continuous_daily_frontier(
        checkpoint=checkpoint,
        source_state=state,
        observation_ids=selected,
        frontier_id="original-captured-bootstrap-again",
        admitted_at=admitted,
        benchmark_instrument_id=inputs.spec.instruments[0][0],
        capture_evidence_class=evidence_class,
    )
    assert duplicate.events == inputs.bootstrap_events
    expected_source = content_digest(
        (
            NORMALIZER_VERSION,
            tuple(
                (observation.semantic_sha256, state.sources[0].semantic_sha256)
                for observation in state.observations
            ),
            admitted,
            inputs.spec.instruments[0][0],
            evidence_class,
        )
    )
    assert duplicate.source_frontier_sha256 == expected_source
    assert codec.encode_record(state) == original
    assert all(
        observation.availability is receipt
        for observation, receipt in zip(state.observations, original_receipts, strict=True)
    )


@pytest.mark.parametrize("evidence_class", ["synthetic_fixture", "provider_https_read"])
def test_new_daily_capture_keeps_original_time_under_late_wakeup(evidence_class):
    inputs, _warmup, _selected = captured_bootstrap(evidence_class)
    checkpoint = start(inputs)
    _unused, state = setup(True)
    observation = state.observations[0]
    raw_before = codec.encode_record(state)
    admitted = observation.known_at + timedelta(hours=1)
    frontier = project_continuous_daily_frontier(
        checkpoint=checkpoint,
        source_state=state,
        observation_ids=(observation.observation_id,),
        frontier_id="late-fixture-wakeup",
        admitted_at=admitted,
        capture_evidence_class=evidence_class,
    )
    (event,) = frontier.events
    assert event.knowledge_at == admitted
    assert event.provenance.raw_sha256 == observation.availability.raw_sha256
    assert (
        event.provenance.observed_at or event.provenance.simulated_available_at
    ) == observation.known_at
    assert codec.encode_record(state) == raw_before


@pytest.mark.parametrize("evidence_class", ["synthetic_fixture", "provider_https_read"])
@pytest.mark.parametrize("phase", ["bootstrap", "frontier"])
def test_capture_class_must_match_the_frozen_checkpoint_mode(evidence_class, phase):
    spec, state, selected = bootstrap_case(True)
    wrong_mode = (
        "recorded_as_observed" if evidence_class == "synthetic_fixture" else "synthetic_observed"
    )
    if phase == "bootstrap":
        with pytest.raises(ValueError, match="cannot be promoted"):
            compile_continuous_bootstrap(
                replace(spec, source_mode=wrong_mode),
                state,
                selected,
                spec.initialized_at,
                capture_evidence_class=evidence_class,
            )
    else:
        checkpoint, state = setup(evidence_class == "synthetic_fixture")
        with pytest.raises(ValueError, match="cannot be promoted"):
            project_continuous_daily_frontier(
                checkpoint=checkpoint,
                source_state=state,
                observation_ids=(state.observations[0].observation_id,),
                frontier_id="class-mismatch",
                admitted_at=state.observations[0].known_at,
                capture_evidence_class=evidence_class,
            )


@pytest.mark.parametrize("evidence_class", ["synthetic_fixture", "provider_https_read"])
def test_modeled_availability_cannot_be_relabelled_as_captured(evidence_class):
    spec, state, selected = bootstrap_case(False)
    if evidence_class == "provider_https_read":
        spec = replace(spec, source_mode="recorded_as_observed")
    with pytest.raises(ValueError, match="original captured source"):
        compile_continuous_bootstrap(
            spec, state, selected, spec.initialized_at, capture_evidence_class=evidence_class
        )


@pytest.mark.parametrize("invalid", ["fixture", "provider", "", 1])
def test_unknown_capture_class_is_rejected(invalid):
    spec, state, selected = bootstrap_case(True)
    with pytest.raises(ValueError, match="unsupported"):
        compile_continuous_bootstrap(
            spec, state, selected, spec.initialized_at, capture_evidence_class=invalid
        )


def test_pure_modeled_legacy_hashes_are_unchanged():
    # Captured before this amendment at normalizer source hash
    # 36a2e71efb9a410cf2b095b643d68a59ecdbcf046ba796cb35746f1499e614d4.
    spec, state, selected = bootstrap_case(False)
    inputs = compile_continuous_bootstrap(
        spec,
        state,
        selected,
        spec.initialized_at,
        benchmark_instrument_id=spec.instruments[0][0],
    )
    checkpoint, state = setup(False)
    frontier = project(checkpoint, state)
    assert (
        inputs.semantic_sha256 == "8bc84339f6a11778d0acfec7bbc72bec58c1f34dacc6df5e978b7a81ddbbb563"
    )
    # The complete frontier also binds the actual checkpoint's elapsed wall
    # budget, so its overall digest is intentionally not a stable golden value.
    assert frontier.previous_checkpoint_sha256 == checkpoint.semantic_sha256
    assert (
        frontier.source_frontier_sha256
        == "f2dbc6ed650360118f48815c521571eacd773314a1c1a5694fae856807bd6133"
    )


def test_concrete_fixture_capture_publishes_only_synthetic_and_preserves_raw_closure(tmp_path):
    case = Case(tmp_path, captured=True)
    try:
        assert case.forward.evidence_class == "synthetic_fixture"
        assert case.inputs.spec.source_mode == "synthetic_observed"
        original_ref = case.initial_ref
        raw = case.artifacts.read(original_ref.object_ref)
        closure = codec.decode_record(raw, ContinuousForwardClosure)
        original_receipts = tuple(
            publication.record.receipt for publication in closure.publications
        )
        case.publish()
        restored = case.store.restore(case.scope)
        assert restored.receipt.commit.source_evidence == original_ref
        assert restored.checkpoint.inputs == case.inputs
        assert all(
            event.provenance.data_class is ResearchDataClass.SYNTHETIC_FIXTURE
            for event in restored.checkpoint.events
        )
        assert case.artifacts.read(original_ref.object_ref) == raw
        resolved = case.forward.resolve(closure)
        assert (
            tuple(publication.record.receipt for publication in resolved.closure.publications)
            == original_receipts
        )
        actual_reader = SqlContinuousForwardSources(
            case.engine, artifacts=case.artifacts, codec=codec, evidence_class="provider_https_read"
        )
        with pytest.raises(ContinuousForwardSourceError, match="PROMOTED"):
            actual_reader.resolve(closure)
    finally:
        case.engine.dispose()


def test_mutated_reader_class_cannot_promote_an_already_owned_capture(tmp_path):
    case = Case(tmp_path, captured=True)
    try:
        closure = codec.decode_record(
            case.artifacts.read(case.initial_ref.object_ref), ContinuousForwardClosure
        )
        resolved = case.forward.resolve(closure)
        case.forward.evidence_class = "provider_https_read"
        with pytest.raises(ContinuousForwardSourceError, match="PROMOTED"):
            case.forward.require_resolved(resolved)
        with (
            case.engine.connect() as connection,
            pytest.raises(ContinuousForwardSourceError, match="PROMOTED"),
        ):
            case.forward.recheck_in_transaction(connection, resolved)
        with pytest.raises(ContinuousForwardSourceError, match="PROMOTED"):
            case.forward.resolve(closure)
        case.forward.evidence_class = "synthetic_fixture"
        case.forward.require_resolved(resolved)
    finally:
        case.engine.dispose()


def test_synthetic_quote_still_cannot_enter_a_recorded_checkpoint(quote_case):  # noqa: F811
    _synthetic_checkpoint, closure, reader = quote_case
    resolved = reader.resolve(closure)
    recorded_checkpoint, _ = setup(True)
    with pytest.raises(ValueError, match="cannot be promoted"):
        project_continuous_quote_frontier(
            checkpoint=recorded_checkpoint, closure=closure, source_state=resolved.state
        )
