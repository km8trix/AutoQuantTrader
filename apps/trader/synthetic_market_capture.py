"""Retain one explicit synthetic daily or quote scenario through actual capture.

Callers supply coherent modeled clock samples and all existing storage ports.
This join creates no storage, samples no host clock, retries no failed capture,
and grants no provider, assignment, risk or delivery authority. Projection remains
responsible for causal selection and quote freshness.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from typing import Literal

from packages.adapters.synthetic_forward_capture import (
    SyntheticForwardCaptureClock,
    SyntheticForwardCaptureTransport,
    SyntheticForwardCaptureVerifier,
)
from packages.application.continuous_forward_replay import replay_continuous_forward_closure
from packages.application.personal_forward_capture import capture_forward
from packages.application.synthetic_capture_scenario import SyntheticCaptureScenario
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
from packages.domain.continuous_quote_contracts import (
    ContinuousQuoteClosure,
    ContinuousQuoteSelection,
)
from packages.domain.forward_capture_contracts import (
    CAPTURE_SCHEMA,
    CaptureClockSample,
    CapturePublication,
    ForwardCaptureRecord,
    ForwardCaptureRequest,
)
from packages.domain.forward_contracts import ForwardDataState, ForwardRequirement
from packages.domain.identifiers import canonical_id
from packages.domain.models import Side
from packages.domain.personal_contracts import content_digest, require_utc
from packages.domain.research_job_contracts import ResearchArtifactStore, ResearchRecordCodec
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication


@dataclass(frozen=True, slots=True)
class SyntheticDailyCapture:
    publication: CapturePublication
    closure: ContinuousForwardClosure
    state: ForwardDataState


@dataclass(frozen=True, slots=True)
class SyntheticQuoteCapture:
    publication: CapturePublication
    closure: ContinuousQuoteClosure
    state: ForwardDataState


def _nanoseconds(delta: timedelta) -> int:
    return ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds) * 1000


def _prepare(
    scenario: SyntheticCaptureScenario,
    samples: tuple[CaptureClockSample, ...],
    admitted_at: datetime,
    kind: Literal["daily", "quote"],
) -> SyntheticForwardCaptureClock:
    if type(scenario) is not SyntheticCaptureScenario:
        raise ValueError("exact synthetic market scenario required")
    request, state = scenario.request, scenario.state
    if type(request) is not ForwardCaptureRequest or type(state) is not ForwardDataState:
        raise ValueError("exact synthetic market request and source state required")
    request.__post_init__()
    state.__post_init__()
    request.calendar.__post_init__()
    request.producer.__post_init__()
    request.source.__post_init__()
    request.journal_key.__post_init__()
    for instrument in request.instruments:
        instrument.__post_init__()
    source = request.source
    if (
        request.kind != kind
        or request.evidence_class != "synthetic_fixture"
        or len(request.instruments) != 1
        or state.mode != "recorded"
        or state.sources != (source,)
        or state.observations
        or state.frontiers
        or source.environment != "production"
        or not source.source_id.startswith("synthetic-capture-")
        or source.identity_reference is None
        or not source.identity_reference.startswith("synthetic-identity-model/")
        or source.rights_reference is None
        or not source.rights_reference.startswith("synthetic-rights-model/")
        or source.entitlement_reference is None
        or not source.entitlement_reference.startswith("synthetic-entitlement-model/")
        or type(scenario.body) is not bytes
        or not 0 < len(scenario.body) <= request.max_response_bytes
        or type(scenario.clock_samples) is not tuple
        or len(scenario.clock_samples) != 3
        or any(type(value) is not CaptureClockSample for value in scenario.clock_samples)
    ):
        raise ValueError("synthetic market scenario profile or empty origin differs")
    # The existing port validates exact types, epoch, regression and deadline.
    clock = SyntheticForwardCaptureClock(request, samples=samples)
    first = samples[0]
    for sample, original in zip(samples, scenario.clock_samples, strict=True):
        require_utc(sample.at, "synthetic capture stage")
        if sample.at != original.at or sample.monotonic_ns - first.monotonic_ns != _nanoseconds(
            sample.at - first.at
        ):
            raise ValueError("synthetic capture script must preserve modeled UTC stage deltas")
    require_utc(admitted_at, "synthetic market admission")
    if admitted_at < samples[-1].at:
        raise ValueError("synthetic market admission predates validated capture")
    if kind == "quote" and not request.session_open <= admitted_at < request.session_close:
        raise ValueError("synthetic quote admission is outside the declared session")
    return clock


def _capture(
    scenario: SyntheticCaptureScenario,
    samples: tuple[CaptureClockSample, ...],
    clock: SyntheticForwardCaptureClock,
    *,
    journal: SqlDurableJournal,
    publisher: SqlForwardCapturePublication,
    artifacts: ResearchArtifactStore,
    codec: ResearchRecordCodec,
) -> CapturePublication:
    if (
        type(journal) is not SqlDurableJournal
        or type(publisher) is not SqlForwardCapturePublication
        or publisher.journal is not journal
        or publisher.engine is not journal._engine
        or journal._codec is not codec
        or journal._types.get(CAPTURE_SCHEMA) is not ForwardCaptureRecord
        or not all(callable(getattr(artifacts, name, None)) for name in ("put", "read"))
        or not all(
            callable(getattr(codec, name, None)) for name in ("encode_record", "decode_record")
        )
    ):
        raise ValueError("original synthetic market capture ports required")
    publisher.require_original()
    request = scenario.request
    publication = capture_forward(
        request,
        scenario.state,
        expected_head=journal.read_head(request.journal_key),
        clock=clock,
        verifier=SyntheticForwardCaptureVerifier(
            request, producer=request.producer, valid_until=request.window_end
        ),
        transport=SyntheticForwardCaptureTransport(request, body=scenario.body),
        journal=journal,
        publisher=publisher,
        artifacts=artifacts,
        codec=codec,
    )
    record = publication.record
    if (
        record.request != request
        or record.raw_object.object_sha256 != sha256(scenario.body).hexdigest()
        or record.raw_object.byte_count != len(scenario.body)
        or tuple(proof.sample for proof in record.verifications) != samples
    ):
        # Exact receipt reuse must not silently discard changed caller inputs.
        # The original receipt/raw object remains retained, including on failure.
        raise ValueError("synthetic market retained capture inputs differ")
    return publication


def capture_synthetic_daily(
    scenario: SyntheticCaptureScenario,
    *,
    samples: tuple[CaptureClockSample, ...],
    admitted_at: datetime,
    journal: SqlDurableJournal,
    publisher: SqlForwardCapturePublication,
    artifacts: ResearchArtifactStore,
    codec: ResearchRecordCodec,
) -> SyntheticDailyCapture:
    """Retain one daily scenario; admission/engine selection remains explicit."""
    clock = _prepare(scenario, samples, admitted_at, "daily")
    publication = _capture(
        scenario,
        samples,
        clock,
        journal=journal,
        publisher=publisher,
        artifacts=artifacts,
        codec=codec,
    )
    closure = ContinuousForwardClosure(
        account_id=scenario.request.journal_key.account_scope,
        closure_id=canonical_id(
            "synthetic-daily-closure/1", content_digest((scenario.request, admitted_at))
        ),
        initial_state=scenario.state,
        publications=(publication,),
        observation_ids=tuple(
            sorted(value.observation_id for value in publication.record.observations)
        ),
        admitted_at=admitted_at,
        evidence_class="synthetic_fixture",
    )
    state = replay_continuous_forward_closure(closure, artifacts=artifacts, codec=codec)
    return SyntheticDailyCapture(publication, closure, state)


def capture_synthetic_quote(
    scenario: SyntheticCaptureScenario,
    *,
    samples: tuple[CaptureClockSample, ...],
    admitted_at: datetime,
    side: Side,
    admitted_monotonic_ns: int,
    journal: SqlDurableJournal,
    publisher: SqlForwardCapturePublication,
    artifacts: ResearchArtifactStore,
    codec: ResearchRecordCodec,
) -> SyntheticQuoteCapture:
    """Retain one selected side quote, without relaxing projection freshness checks."""
    clock = _prepare(scenario, samples, admitted_at, "quote")
    if (
        type(side) is not Side
        or type(admitted_monotonic_ns) is not int
        or not 0 <= admitted_monotonic_ns < 2**63
        or admitted_monotonic_ns - samples[-1].monotonic_ns
        != _nanoseconds(admitted_at - samples[-1].at)
    ):
        raise ValueError("synthetic quote side or admission clock differs")
    publication = _capture(
        scenario,
        samples,
        clock,
        journal=journal,
        publisher=publisher,
        artifacts=artifacts,
        codec=codec,
    )
    request = scenario.request
    (instrument,) = request.instruments
    (observation,) = publication.record.observations
    closure = ContinuousQuoteClosure(
        account_id=request.journal_key.account_scope,
        closure_id=canonical_id(
            "synthetic-quote-closure/1",
            content_digest((request, side, admitted_at, samples[0].boot_id, admitted_monotonic_ns)),
        ),
        initial_state=scenario.state,
        publications=(publication,),
        selections=(
            ContinuousQuoteSelection(
                observation.observation_id,
                ForwardRequirement(
                    request.source.source_id,
                    instrument.instrument_id,
                    instrument.symbol,
                    request.session,
                    "quote",
                ),
                side,
                request.producer,
            ),
        ),
        admitted_at=admitted_at,
        boot_id=samples[0].boot_id,
        admitted_monotonic_ns=admitted_monotonic_ns,
        evidence_class="synthetic_fixture",
    )
    state = replay_continuous_forward_closure(closure, artifacts=artifacts, codec=codec)
    return SyntheticQuoteCapture(publication, closure, state)
