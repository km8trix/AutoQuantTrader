"""Project exact retained side quotes through the existing quote normalizer."""

from datetime import timedelta

from packages.application.personal_forward_data import close_frontier
from packages.application.runtime_quote_marks import (
    RuntimeQuoteMarkRequest,
    build_runtime_quote_marks,
)
from packages.domain.accounting_contracts import AccountingCommand
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier, ContinuousEngineInputs
from packages.domain.continuous_quote_contracts import ContinuousQuoteClosure
from packages.domain.engine_contracts import EngineEvent, ObservationProvenance
from packages.domain.forward_contracts import CaptureReceipt, ForwardDataState
from packages.domain.personal_contracts import content_digest
from packages.domain.research_dataset import ResearchDataClass

QUOTE_FRONTIER_VERSION = "personal-continuous-quote-frontier/1"


def project_continuous_quote_frontier(
    *,
    checkpoint: CausalEngineCheckpoint,
    closure: ContinuousQuoteClosure,
    source_state: ForwardDataState,
) -> ClosedEngineFrontier:
    """Source-only marks at the original closure instant; no activation or dispatch.

    The storage composer authenticates capture journals and the operating source
    producer authenticates the original clock/boot receipt. This pure projection
    cannot promote a synthetic capture or establish provider access rights.
    """
    if type(checkpoint.inputs) is not ContinuousEngineInputs:
        raise ValueError("continuous quote projection requires a continuous checkpoint")
    closure.__post_init__()
    spec = checkpoint.inputs.spec
    if closure.account_id != spec.account_id or closure.admitted_at <= checkpoint.now:
        raise ValueError("continuous quote closure account or original boundary differs")
    recorded = closure.evidence_class == "provider_https_read"
    if recorded != (spec.source_mode == "recorded_as_observed"):
        raise ValueError("continuous quote source class cannot be promoted")
    if source_state.mode != "recorded" or source_state.sources != closure.initial_state.sources:
        raise ValueError("continuous quote source origin differs")
    by_id = {value.observation_id: value for value in source_state.observations}
    by_source = {value.source_id: value for value in source_state.sources}
    captured = {
        observation.observation_id: publication.record
        for publication in closure.publications
        for observation in publication.record.observations
    }
    sessions = {session.session_label: session for session in spec.calendar.sessions}
    instruments = dict(spec.instruments)
    requirements = tuple(value.expected for value in closure.selections)
    selected = close_frontier(
        source_state,
        frontier_id=closure.closure_id,
        requirements=requirements,
        cutoff=closure.admitted_at + timedelta(microseconds=1),
        closed_at=closure.admitted_at,
    )
    if selected.disposition != "closed" or selected.frontier is None or selected.frontier.missing:
        raise ValueError("continuous quote source selection is incomplete or ambiguous")
    if dict(selected.frontier.selected) != {
        value.expected.semantic_sha256: value.observation_id for value in closure.selections
    }:
        raise ValueError("continuous quote selection hides a newer known observation")
    old_events = {event.event_id: event for event in checkpoint.events}
    events = []
    for selection in closure.selections:
        observation = by_id.get(selection.observation_id)
        source = by_source.get(selection.expected.source_id)
        session = sessions.get(selection.expected.session)
        record = captured.get(selection.observation_id)
        if (
            observation is None
            or source is None
            or session is None
            or record is None
            or observation not in record.observations
            or record.request.source != source
            or record.request.session != session.session_label
            or record.request.session_open != session.opens_at
            or record.request.session_close != session.closes_at
            or instruments.get(selection.expected.instrument_id) != selection.expected.symbol
            or not session.opens_at <= closure.admitted_at < session.closes_at
            or observation.source_sequence is not None
        ):
            raise ValueError("continuous quote instrument, session or sequence is unsupported")
        request = RuntimeQuoteMarkRequest(
            observation, source, selection.expected, selection.side, selection.producer
        )
        (mark,) = build_runtime_quote_marks(
            (request,),
            environment=source.environment,
            account_scope=closure.account_id,
            evaluated_at=closure.admitted_at,
            boot_id=closure.boot_id,
            evaluated_monotonic_ns=closure.admitted_monotonic_ns,
        )
        if mark.economic_at < session.opens_at:
            raise ValueError("continuous quote side predates its actual session")
        receipt = observation.availability
        assert isinstance(receipt, CaptureReceipt)
        command = AccountingCommand(mark.mark_id, mark)
        provenance = ObservationProvenance(
            data_class=(
                "recorded_as_observed" if recorded else ResearchDataClass.SYNTHETIC_FIXTURE
            ),
            source_namespace=source.provider + ".captured-side-quotes",
            normalized_sha256=content_digest(command),
            observed_at=receipt.validated_at if recorded else None,
            simulated_available_at=None if recorded else receipt.validated_at,
            assumption_id=None if recorded else "synthetic-capture-replay/1",
            raw_sha256=receipt.raw_sha256,
            limitations=("synthetic capture does not qualify provider access",)
            if not recorded
            else (),
        )
        event = EngineEvent(
            mark.mark_id,
            mark.economic_at,
            closure.admitted_at,
            command,
            provenance,
        )
        original = old_events.get(event.event_id)
        if original is not None:
            if (
                original.payload != event.payload
                or original.economic_at != event.economic_at
                or original.provenance != event.provenance
                or original.predecessor_ids
                or original.source_sequence is not None
            ):
                raise ValueError("continuous quote identity differs from its original event")
            event = original
        events.append(event)
    return ClosedEngineFrontier(
        frontier_id=closure.closure_id,
        stream_id=spec.run_id,
        previous_checkpoint_sha256=checkpoint.semantic_sha256,
        source_frontier_sha256=content_digest((QUOTE_FRONTIER_VERSION, closure)),
        knowledge_at=closure.admitted_at,
        events=tuple(sorted(events, key=lambda event: event.event_id)),
    )
