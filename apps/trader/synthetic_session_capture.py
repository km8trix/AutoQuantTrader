"""Capture a finite synthetic warmup through existing ports and the sole compiler.

The caller owns all journal/publication/artifact/codec ports. This module creates
no paths, databases, account, assignment or controls. Its modeled UTC/monotonic
timeline is not actual host continuity or provider qualification.

This capture seam supports the current single-instrument synthetic builder and
one to 64 serial warmup observations. The pure input builder's zero/larger warmup
support and the engine's multi-instrument support are unchanged; an empty capture
closure is not a valid retained-source contract.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from packages.adapters.synthetic_forward_capture import (
    SyntheticForwardCaptureClock,
    SyntheticForwardCaptureTransport,
    SyntheticForwardCaptureVerifier,
)
from packages.application.continuous_forward_replay import replay_continuous_forward_closure
from packages.application.continuous_source_events import compile_continuous_bootstrap
from packages.application.personal_forward_capture import capture_forward, replay_capture
from packages.application.synthetic_capture_scenario import (
    SyntheticCaptureScenario,
    synthetic_daily_capture_scenario,
)
from packages.application.synthetic_continuous_inputs import SyntheticContinuousInputs
from packages.domain.continuous_engine_contracts import ContinuousEngineInputs
from packages.domain.continuous_forward_contracts import (
    MAX_CLOSURE_CAPTURES,
    MAX_CLOSURE_RAW_BYTES,
    ContinuousForwardClosure,
)
from packages.domain.durable_journal_contracts import JournalHead
from packages.domain.engine_contracts import DailyPrice, EngineEvent
from packages.domain.forward_capture_contracts import (
    CAPTURE_SCHEMA,
    CapturePublication,
    ForwardCaptureRecord,
)
from packages.domain.forward_contracts import ForwardDataState
from packages.domain.identifiers import canonical_id
from packages.domain.personal_contracts import VersionPin
from packages.domain.research_dataset import ResearchDataClass, modeled_daily_availability
from packages.domain.research_job_contracts import ResearchArtifactStore, ResearchRecordCodec
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication


@dataclass(frozen=True, slots=True)
class SyntheticBootstrapCapture:
    inputs: ContinuousEngineInputs
    closure: ContinuousForwardClosure
    state: ForwardDataState


def _prepare_scenarios(
    synthetic: SyntheticContinuousInputs, calendar_pin: VersionPin, producer_pin: VersionPin
) -> tuple[SyntheticCaptureScenario, ...]:
    if (
        type(synthetic) is not SyntheticContinuousInputs
        or type(synthetic.inputs) is not ContinuousEngineInputs
    ):
        raise ValueError("exact synthetic continuous inputs required")
    inputs = synthetic.inputs
    inputs.__post_init__()
    spec = inputs.spec
    spec.__post_init__()
    if (
        spec.environment != "stateful_simulation"
        or spec.source_mode != "synthetic_observed"
        or spec.live_authorized is not False
    ):
        raise ValueError("capture bootstrap requires live-disabled synthetic inputs")
    if len(spec.instruments) != 1:
        raise ValueError("synthetic capture bootstrap requires one declared instrument")
    if not 1 <= len(inputs.bootstrap_events) <= MAX_CLOSURE_CAPTURES:
        raise ValueError("synthetic capture bootstrap requires 1..64 warmup observations")
    for pin in (calendar_pin, producer_pin):
        if type(pin) is not VersionPin:
            raise ValueError("exact synthetic capture calendar and producer pins required")
        pin.__post_init__()
    calendar = {session.session_label: session for session in spec.calendar.sessions}
    instruments = dict(spec.instruments)
    prices = []
    for event in inputs.bootstrap_events:
        if type(event) is not EngineEvent or type(event.payload) is not DailyPrice:
            raise ValueError("synthetic bootstrap accepts daily prices only")
        event.__post_init__()
        price = event.payload
        session = calendar.get(price.session)
        if (
            session is None
            or instruments.get(price.instrument_id) != price.symbol
            or price.session not in spec.window.warmup_sessions
            or event.provenance.data_class is not ResearchDataClass.SYNTHETIC_FIXTURE
            or event.provenance.observed_at is not None
            or event.economic_at != session.closes_at
            or event.knowledge_at != modeled_daily_availability(price.session)
            or event.provenance.simulated_available_at != event.knowledge_at
        ):
            raise ValueError("synthetic bootstrap price scope or causal model differs")
        prices.append((price, session))
    expected = {
        (instrument_id, session)
        for instrument_id, _ in spec.instruments
        for session in spec.window.warmup_sessions
    }
    actual = {(price.instrument_id, price.session) for price, _ in prices}
    if actual != expected or len(prices) != len(expected):
        raise ValueError("synthetic bootstrap requires complete declared warmup coverage")
    scenarios = tuple(
        synthetic_daily_capture_scenario(
            price=price,
            session=session,
            capture_id=canonical_id(
                "synthetic-bootstrap-capture/1",
                spec.account_binding_sha256,
                price.semantic_sha256,
                calendar_pin.semantic_sha256,
                producer_pin.semantic_sha256,
            ),
            account_scope=spec.account_id,
            calendar_pin=calendar_pin,
            producer_pin=producer_pin,
            evidence_class="synthetic_fixture",
        )
        for price, session in sorted(
            prices, key=lambda item: (item[0].session, item[0].instrument_id)
        )
    )
    if sum(len(scenario.body) for scenario in scenarios) > MAX_CLOSURE_RAW_BYTES:
        raise ValueError("synthetic bootstrap raw capture bound exceeded")
    origin = scenarios[0].clock_samples[0].at
    previous = origin
    coherent = []
    for scenario in scenarios:
        if scenario.clock_samples[0].at < previous:
            raise ValueError("synthetic warmup capture scripts overlap or regress")
        samples = []
        for sample in scenario.clock_samples:
            delta = sample.at - origin
            microseconds = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
            monotonic_ns = 1000000000 + microseconds * 1000
            if not 0 <= monotonic_ns < 2**63:
                raise ValueError("synthetic warmup clock exceeds its original range")
            samples.append(replace(sample, monotonic_ns=monotonic_ns))
        if samples[-1].at > spec.initialized_at:
            raise ValueError("synthetic warmup capture is not known at initialization")
        coherent.append(replace(scenario, clock_samples=tuple(samples)))
        previous = samples[-1].at
    return tuple(coherent)


def _require_ports(
    journal: SqlDurableJournal,
    publisher: SqlForwardCapturePublication,
    artifacts: ResearchArtifactStore,
    codec: ResearchRecordCodec,
) -> None:
    if (
        type(journal) is not SqlDurableJournal
        or type(publisher) is not SqlForwardCapturePublication
        or publisher.journal is not journal
        or publisher.engine is not journal._engine
        or journal._codec is not codec
        or journal._types.get(CAPTURE_SCHEMA) is not ForwardCaptureRecord
    ):
        raise ValueError("original synthetic capture journal/publisher/codec graph required")
    if not all(callable(getattr(artifacts, name, None)) for name in ("put", "read")) or not all(
        callable(getattr(codec, name, None)) for name in ("encode_record", "decode_record")
    ):
        raise ValueError("explicit synthetic capture artifact and codec ports required")
    publisher.require_original()


def capture_synthetic_bootstrap(
    synthetic: SyntheticContinuousInputs,
    *,
    calendar_pin: VersionPin,
    producer_pin: VersionPin,
    journal: SqlDurableJournal,
    publisher: SqlForwardCapturePublication,
    artifacts: ResearchArtifactStore,
    codec: ResearchRecordCodec,
) -> SyntheticBootstrapCapture:
    """Retain actual synthetic receipts and compile their complete warmup.

    Input/scope/script/graph checks precede port I/O. Failed captures are not
    erased or retried here. Existing exact collector receipts supply idempotency.
    UTC-derived integer monotonic samples describe only the declared model.
    """
    scenarios = _prepare_scenarios(synthetic, calendar_pin, producer_pin)
    _require_ports(journal, publisher, artifacts, codec)
    sources = {scenario.request.source.source_id: scenario.request.source for scenario in scenarios}
    initial = ForwardDataState(tuple(sources[key] for key in sorted(sources)), "recorded")
    state = initial
    publications: list[CapturePublication] = []
    heads: dict[str, JournalHead] = {}
    for scenario in scenarios:
        request = scenario.request
        stream = request.journal_key.semantic_sha256
        if stream not in heads:
            heads[stream] = journal.read_head(request.journal_key)
        publication = capture_forward(
            request,
            state,
            expected_head=heads[stream],
            clock=SyntheticForwardCaptureClock(request, samples=scenario.clock_samples),
            verifier=SyntheticForwardCaptureVerifier(
                request, producer=producer_pin, valid_until=request.window_end
            ),
            transport=SyntheticForwardCaptureTransport(request, body=scenario.body),
            journal=journal,
            publisher=publisher,
            artifacts=artifacts,
            codec=codec,
        )
        publications.append(publication)
        heads[stream] = publication.journal_receipt.committed_head
        state = replay_capture(publication.record, state, artifacts=artifacts)
    selected = tuple(sorted(observation.observation_id for observation in state.observations))
    spec = synthetic.inputs.spec
    closure = ContinuousForwardClosure(
        account_id=spec.account_id,
        closure_id=canonical_id("synthetic-bootstrap-closure/1", spec.run_id, selected),
        initial_state=initial,
        publications=tuple(publications),
        observation_ids=selected,
        admitted_at=spec.initialized_at,
        evidence_class="synthetic_fixture",
    )
    retained = replay_continuous_forward_closure(closure, artifacts=artifacts, codec=codec)
    if retained != state:
        raise ValueError("synthetic bootstrap retained replay differs")
    benchmark = next(
        (instrument_id for instrument_id, symbol in spec.instruments if symbol == "SPY"), None
    )
    inputs = compile_continuous_bootstrap(
        spec,
        retained,
        selected,
        spec.initialized_at,
        benchmark_instrument_id=benchmark,
        capture_evidence_class="synthetic_fixture",
    )
    return SyntheticBootstrapCapture(inputs, closure, retained)
