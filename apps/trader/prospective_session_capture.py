"""Retain synthetic warmup bytes with actual, unqualified acquisition stages.

The caller owns existing fresh temporary source storage. Only selected capture
streams are checked for emptiness here; this is not whole-database attestation.
No account, financial genesis, lease, final closure or initialization is created.
Synthetic price/rights declarations never qualify provider access or UTC health.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from datetime import timedelta
from uuid import uuid4

from apps.trader.synthetic_session_capture import _prepare_scenarios, _require_ports
from apps.trader.synthetic_session_genesis import _require_input_profile
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.adapters.synthetic_forward_capture import (
    SyntheticForwardCaptureTransport,
    SyntheticForwardCaptureVerifier,
)
from packages.application.personal_forward_capture import capture_forward, replay_capture
from packages.application.synthetic_continuous_inputs import SyntheticContinuousInputs
from packages.domain.clock import SystemClock
from packages.domain.durable_journal_contracts import JournalHead, empty_head
from packages.domain.engine_contracts import DailyPrice, EngineEvent
from packages.domain.forward_capture_contracts import (
    CaptureClockSample,
    CapturePublication,
    ForwardCaptureRequest,
)
from packages.domain.forward_contracts import ForwardDataState
from packages.domain.identifiers import canonical_id
from packages.domain.personal_contracts import VersionPin, content_digest, require_utc
from packages.domain.research_dataset import ResearchDataClass, modeled_daily_availability
from packages.domain.research_job_contracts import ResearchRecordCodec
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication


@dataclass(frozen=True, slots=True)
class ProspectiveSyntheticWarmupRetention:
    """Declared plan and original capture results, not an authentication token."""

    plan: SyntheticContinuousInputs
    plan_sha256: str
    initial_state: ForwardDataState
    publications: tuple[CapturePublication, ...]
    state: ForwardDataState


class _ActualSamples:
    """Fresh process UTC/monotonic observations, with no accuracy/health claim."""

    def __init__(self) -> None:
        self._clock = SystemClock()
        self._epoch = "prospective-synthetic-acquisition/1:" + uuid4().hex
        self._previous: CaptureClockSample | None = None

    def sample(self) -> CaptureClockSample:
        instant = self._clock.now()
        require_utc(instant, "actual synthetic acquisition UTC")
        monotonic_ns = time.monotonic_ns()
        result = CaptureClockSample(instant, monotonic_ns, self._epoch)
        previous = self._previous
        if previous is not None and (
            result.at < previous.at or result.monotonic_ns < previous.monotonic_ns
        ):
            raise ValueError("actual synthetic acquisition clocks regressed")
        self._previous = result
        return result


class _ActualCaptureClock:
    """Three actual receipt stages; current checks also take fresh samples."""

    def __init__(self, samples: _ActualSamples) -> None:
        self._samples = samples
        self._issued = 0

    def sample(self) -> CaptureClockSample:
        if self._issued >= 3:
            raise ValueError("actual synthetic capture stages exhausted")
        result = self._samples.sample()
        self._issued += 1
        return result

    def current_sample(self) -> CaptureClockSample:
        if self._issued == 0:
            raise ValueError("actual synthetic capture has no original stage")
        return self._samples.sample()


def _require_plan(plan: SyntheticContinuousInputs) -> str:
    if type(plan) is not SyntheticContinuousInputs:
        raise ValueError("exact prospective synthetic inputs required")
    _require_input_profile(plan.inputs)
    spec = plan.inputs.spec
    if (
        spec.instruments != (("US-ETF-SPY", "SPY"),)
        or len(spec.window.warmup_sessions) != 2
        or not 3 <= len(spec.window.warmup_sessions) + len(spec.window.scored_sessions) <= 5000
        or type(plan.daily_events) is not tuple
        or len(plan.daily_events) != len(spec.window.scored_sessions)
    ):
        raise ValueError("prospective retention requires the fixed two-warmup SPY profile")
    for pin in spec.pins:
        if type(pin) is not VersionPin:
            raise ValueError("exact prospective build pins required")
        pin.__post_init__()
    sessions = {session.session_label: session for session in spec.calendar.sessions}
    scored = []
    for event in plan.daily_events:
        if type(event) is not EngineEvent or type(event.payload) is not DailyPrice:
            raise ValueError("prospective scored inputs must remain synthetic daily values")
        event.__post_init__()
        price = event.payload
        session = sessions.get(price.session)
        if (
            session is None
            or (price.instrument_id, price.symbol) != ("US-ETF-SPY", "SPY")
            or event.economic_at != session.closes_at
            or event.knowledge_at != modeled_daily_availability(price.session)
            or event.provenance.data_class is not ResearchDataClass.SYNTHETIC_FIXTURE
            or event.provenance.observed_at is not None
            or event.provenance.simulated_available_at != event.knowledge_at
        ):
            raise ValueError("prospective scored input scope or modeled time differs")
        scored.append(price.session)
    if tuple(scored) != spec.window.scored_sessions:
        raise ValueError("prospective scored coverage or order differs")
    return content_digest((plan.inputs, plan.daily_events))


def retain_prospective_synthetic_warmup(
    plan: SyntheticContinuousInputs,
    *,
    calendar_pin: VersionPin,
    producer_pin: VersionPin,
    journal: SqlDurableJournal,
    publisher: SqlForwardCapturePublication,
    artifacts: LocalResearchArtifactStore,
    codec: ResearchRecordCodec,
) -> ProspectiveSyntheticWarmupRetention:
    """Retain one fresh synthetic warmup without finalizing initialization.

    Historical model availability remains in the bound plan. Actual stage times
    describe this local acquisition only, not provider publication or UTC health.
    The original verifier's synthetic-modeled-clock reference remains a model
    declaration; actual local stage samples do not turn it into measured proof.
    No implicit adoption/retry/cleanup occurs; failures preserve partial facts.
    The original collector owns all deadlines, receipts and source publication.
    """
    plan_sha256 = _require_plan(plan)
    scenarios = _prepare_scenarios(plan, calendar_pin, producer_pin)
    if type(artifacts) is not LocalResearchArtifactStore:
        raise ValueError("original private local synthetic artifact owner required")
    samples = _ActualSamples()
    before = samples.sample()
    if any(event.knowledge_at > before.at for event in plan.inputs.bootstrap_events):
        raise ValueError("synthetic warmup model availability remains future")
    _require_ports(journal, publisher, artifacts, codec)
    heads: dict[str, JournalHead] = {}
    for scenario in scenarios:
        key = scenario.request.journal_key
        stream = key.semantic_sha256
        if stream not in heads:
            actual = journal.read_head(key)
            if actual != empty_head(key):
                raise ValueError("prospective retention requires fresh selected capture streams")
            heads[stream] = actual
    sources = {scenario.request.source.source_id: scenario.request.source for scenario in scenarios}
    initial = ForwardDataState(tuple(sources[key] for key in sorted(sources)), "recorded")
    state = initial
    publications: list[CapturePublication] = []
    invocation = uuid4().hex
    for scenario in scenarios:
        window_start = samples.sample().at
        # The pure scenario's bytes/declarations are reused. Its historical
        # window, scripted samples and receipt-stage assumption are not used.
        request: ForwardCaptureRequest = replace(
            scenario.request,
            capture_id=canonical_id(
                "prospective-synthetic-warmup/1",
                plan_sha256,
                invocation,
                scenario.request.capture_id,
            ),
            window_start=window_start,
            window_end=window_start + timedelta(milliseconds=3000),
        )
        stream = request.journal_key.semantic_sha256
        publication = capture_forward(
            request,
            state,
            expected_head=heads[stream],
            clock=_ActualCaptureClock(samples),
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
    if content_digest((plan.inputs, plan.daily_events)) != plan_sha256:
        raise ValueError("original prospective plan changed during retention")
    return ProspectiveSyntheticWarmupRetention(
        plan=plan,
        plan_sha256=plan_sha256,
        initial_state=initial,
        publications=tuple(publications),
        state=state,
    )
