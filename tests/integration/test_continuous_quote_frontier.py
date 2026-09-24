"""Actual SQLite/raw replay with declared synthetic provider-shaped observations."""

from dataclasses import replace
from datetime import timedelta
from zoneinfo import ZoneInfo

import pytest
import sqlalchemy as sa

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.continuous_quote_frontier import project_continuous_quote_frontier
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
from packages.domain.continuous_quote_contracts import (
    ContinuousQuoteClosure,
    ContinuousQuoteSelection,
)
from packages.domain.forward_capture_contracts import CaptureClockSample
from packages.domain.forward_contracts import ForwardDataState, ForwardRequirement
from packages.domain.models import Side
from packages.persistence.continuous_forward_sources import (
    ContinuousForwardSourceError,
    SqlContinuousForwardSources,
)
from packages.persistence.database import _repeatable_read_transaction, create_database_engine
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.schema import metadata
from tests.integration.test_personal_forward_capture_journal import capture, journal
from tests.unit.test_continuous_source_events import advance, project, setup
from tests.unit.test_personal_forward_capture import Clock, Transport, quote_body, request


@pytest.fixture
def case(tmp_path):
    checkpoint, daily_sources = setup(False)
    checkpoint = advance(checkpoint, project(checkpoint, daily_sources))
    hold = checkpoint.state.commitments[0]
    at = hold.not_before
    session = next(
        s for s in checkpoint.inputs.spec.calendar.sessions if s.session_label == at.date()
    )
    req = request()
    source = replace(req.source, account_scope=checkpoint.state.account_id)
    req = replace(
        req,
        source=source,
        instruments=(replace(req.instruments[0], instrument_id=hold.instrument_id),),
        session=session.session_label,
        session_open=session.opens_at,
        session_close=session.closes_at,
        window_start=session.opens_at,
        window_end=session.closes_at,
        journal_key=replace(
            req.journal_key,
            account_scope=source.account_scope,
            source_scope_sha256=source.semantic_sha256,
        ),
    )
    state = ForwardDataState((source,), "recorded")
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/quote.sqlite")
    metadata.create_all(engine, tables=JOURNAL_TABLES)
    artifacts = LocalResearchArtifactStore(tmp_path / "objects")
    side_time = at.astimezone(ZoneInfo("America/New_York")).strftime("%H:%M:%S %Z %m-%d-%Y")
    body = quote_body(
        dateTimeUTC=int(at.timestamp()),
        All={"bid": 99, "ask": 100, "bidTime": side_time, "askTime": side_time},
    )
    publication = capture(
        req, state, journal(engine), artifacts, clock=Clock(at), transport=Transport(body)
    )
    observation = publication.record.observations[0]
    closure = ContinuousQuoteClosure(
        account_id=checkpoint.state.account_id,
        closure_id="actual-retained-fixture-quotes",
        initial_state=state,
        publications=(publication,),
        selections=(
            ContinuousQuoteSelection(
                observation.observation_id,
                ForwardRequirement(source.source_id, hold.instrument_id, "SPY", at.date(), "quote"),
                Side.BUY,
                req.producer,
            ),
        ),
        admitted_at=at + timedelta(milliseconds=300),
        boot_id=publication.record.receipt.boot_id,
        admitted_monotonic_ns=1300000000,
        evidence_class="synthetic_fixture",
    )
    store = SqlContinuousForwardSources(
        engine, artifacts=artifacts, codec=personal_codec, evidence_class="synthetic_fixture"
    )
    yield checkpoint, closure, store
    engine.dispose()


def test_original_quote_capture_replays_through_actual_engine_without_activation(case):
    checkpoint, closure, store = case
    resolved = store.resolve(closure)
    frontier = project_continuous_quote_frontier(
        checkpoint=checkpoint, closure=closure, source_state=resolved.state
    )
    (event,) = frontier.events
    mark = event.payload.payload
    assert mark.price == 100 and mark.basis == "runtime_quote_ask_v1"
    assert mark.economic_at == closure.publications[0].record.observations[0].payload.ask_at
    assert mark.knowledge_at == closure.publications[0].record.receipt.validated_at
    assert event.knowledge_at == closure.admitted_at
    assert event.source_sequence is None and event.provenance.vendor_published_at is None
    first = advance(checkpoint, frontier)
    restarted = personal_codec.decode_record(
        personal_codec.encode_record(checkpoint), type(checkpoint)
    )
    later = advance(restarted, frontier)
    assert first.runtime_decisions == later.runtime_decisions
    assert (
        first.state == later.state and first.current == later.current and first.trace == later.trace
    )
    assert first.state.commitments == checkpoint.state.commitments
    assert first.state.broker_events == checkpoint.state.broker_events == ()
    assert advance(first, frontier) is first
    assert first.current.snapshot.point.knowledge_at == closure.admitted_at
    with _repeatable_read_transaction(store.engine) as connection:
        store.recheck_in_transaction(connection, resolved)


@pytest.mark.parametrize("change", ["receipt_age", "mono_age", "boot", "side", "class"])
def test_original_quote_receipts_cannot_be_refreshed_or_promoted(case, change):
    checkpoint, closure, store = case
    resolved = store.resolve(closure)
    if change == "receipt_age":
        closure = replace(closure, admitted_at=closure.admitted_at + timedelta(seconds=1))
    elif change == "mono_age":
        closure = replace(closure, admitted_monotonic_ns=2300000000)
    elif change == "boot":
        closure = replace(closure, boot_id="other-boot")
    elif change == "class":
        with pytest.raises(ContinuousForwardSourceError, match="PROMOTED"):
            SqlContinuousForwardSources(
                store.engine,
                artifacts=store.artifacts,
                codec=store.codec,
                evidence_class="provider_https_read",
            ).resolve(closure)
        return
    else:
        closure = replace(closure, selections=(replace(closure.selections[0], side=Side.SELL),))
        frontier = project_continuous_quote_frontier(
            checkpoint=checkpoint, closure=closure, source_state=resolved.state
        )
        assert frontier.events[0].payload.payload.price == 99
        assert frontier.events[0].payload.payload.basis == "runtime_quote_bid_v1"
        return
    with pytest.raises(ValueError):
        project_continuous_quote_frontier(
            checkpoint=checkpoint, closure=closure, source_state=resolved.state
        )


def test_daily_schema_cannot_relabel_quote_capture_and_selected_scope_is_exact(case):
    checkpoint, closure, store = case
    with pytest.raises(ValueError, match="SCOPE_CLASS"):
        ContinuousForwardClosure(
            account_id=closure.account_id,
            closure_id=closure.closure_id,
            initial_state=closure.initial_state,
            publications=closure.publications,
            observation_ids=closure.observation_ids,
            admitted_at=closure.admitted_at,
            evidence_class=closure.evidence_class,
        )
    resolved = store.resolve(closure)
    changed = replace(
        closure,
        selections=(
            replace(
                closure.selections[0],
                expected=replace(closure.selections[0].expected, symbol="QQQ"),
            ),
        ),
    )
    with pytest.raises(ValueError):
        project_continuous_quote_frontier(
            checkpoint=checkpoint, closure=changed, source_state=resolved.state
        )


def test_original_quote_journal_tamper_blocks_final_publication(case):
    _, closure, store = case
    resolved = store.resolve(closure)
    with store.engine.begin() as connection:
        connection.execute(sa.update(journal_entries).values(payload=b"{}"))
    with (
        _repeatable_read_transaction(store.engine) as connection,
        pytest.raises(ContinuousForwardSourceError),
    ):
        store.recheck_in_transaction(connection, resolved)


def test_final_quote_source_check_runs_no_object_codec_or_normalizer(case, monkeypatch):
    _, closure, store = case
    resolved = store.resolve(closure)

    def forbidden(*args, **kwargs):
        raise AssertionError("source replay under SQL lock")

    monkeypatch.setattr(store.artifacts, "read", forbidden)
    monkeypatch.setattr(personal_codec, "decode_record", forbidden)
    monkeypatch.setattr(personal_codec, "encode_record", forbidden)
    with _repeatable_read_transaction(store.engine) as connection:
        store.recheck_in_transaction(connection, resolved)


def test_old_selection_cannot_hide_a_later_retained_quote_capture(case):
    checkpoint, closure, store = case
    resolved = store.resolve(closure)
    first = closure.publications[0]
    at = first.record.receipt.requested_at
    samples = [
        CaptureClockSample(
            at + timedelta(milliseconds=n), 1000000000 + n * 1000000, closure.boot_id
        )
        for n in (400, 500, 600)
    ]
    body = store.artifacts.read(first.record.raw_object)
    second = capture(
        replace(first.record.request, capture_id="second-quote"),
        resolved.state,
        journal(store.engine),
        store.artifacts,
        clock=Clock(samples=samples),
        transport=Transport(body),
        head=first.journal_receipt.committed_head,
    )
    changed = replace(
        closure,
        closure_id="two-quotes",
        publications=(first, second),
        admitted_at=at + timedelta(milliseconds=700),
        admitted_monotonic_ns=1700000000,
    )
    current = store.resolve(changed)
    with pytest.raises(ValueError, match="hides a newer known observation"):
        project_continuous_quote_frontier(
            checkpoint=checkpoint, closure=changed, source_state=current.state
        )
    changed = replace(
        changed,
        selections=(
            replace(
                closure.selections[0], observation_id=second.record.observations[0].observation_id
            ),
        ),
    )
    selected = project_continuous_quote_frontier(
        checkpoint=checkpoint, closure=changed, source_state=current.state
    )
    assert selected.events[0].payload.payload.knowledge_at == second.record.receipt.validated_at


def test_capture_session_boundaries_must_match_the_engine_calendar(case):
    checkpoint, closure, store = case
    resolved = store.resolve(closure)
    calendar = checkpoint.inputs.spec.calendar
    calendar = replace(
        calendar,
        sessions=tuple(
            replace(s, closes_at=s.closes_at + timedelta(minutes=1))
            if s.session_label == closure.selections[0].expected.session
            else s
            for s in calendar.sessions
        ),
    )
    changed = replace(
        checkpoint,
        inputs=replace(checkpoint.inputs, spec=replace(checkpoint.inputs.spec, calendar=calendar)),
    )
    with pytest.raises(ValueError, match="session or sequence"):
        project_continuous_quote_frontier(
            checkpoint=changed, closure=closure, source_state=resolved.state
        )
