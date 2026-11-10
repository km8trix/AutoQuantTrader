"""Retained fixture quotes atomically extend the actual C/B account prefix."""

from dataclasses import replace
from datetime import timedelta
from zoneinfo import ZoneInfo

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.application.continuous_quote_frontier import project_continuous_quote_frontier
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.continuous_quote_contracts import (
    CONTINUOUS_QUOTE_CLOSURE_SCHEMA,
    ContinuousQuoteClosure,
    ContinuousQuoteSelection,
)
from packages.domain.forward_contracts import ForwardDataState, ForwardRequirement
from packages.domain.models import Side
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.daily_runtime_risk_schema import daily_runtime_hold_heads
from packages.persistence.durable_journal_schema import journal_entries
from tests.integration.test_continuous_composition import Case
from tests.integration.test_personal_forward_capture_journal import capture, journal
from tests.unit.test_personal_forward_capture import Clock, Transport, quote_body, request


@pytest.fixture
def case(tmp_path):
    value = Case(tmp_path, captured=False)
    value.publish()
    session = next(
        s
        for s in value.inputs.spec.calendar.sessions
        if s.session_label == value.inputs.spec.window.scored_sessions[0]
    )
    at = session.opens_at
    instrument_id = value.inputs.spec.instruments[0][0]
    value.h.coordinator.release(value.h.lease.fence)
    value.h.clock.instant = at + timedelta(milliseconds=300)
    value.h.lease = value.h.coordinator.acquire("owner")
    value.store = value.new_store()
    previous = value.store.restore(value.scope)
    session = next(s for s in value.inputs.spec.calendar.sessions if s.session_label == at.date())
    req = request()
    source = replace(req.source, account_scope=value.h.account)
    req = replace(
        req,
        source=source,
        instruments=(replace(req.instruments[0], instrument_id=instrument_id),),
        session=session.session_label,
        session_open=session.opens_at,
        session_close=session.closes_at,
        window_start=session.opens_at,
        window_end=session.closes_at,
        journal_key=replace(
            req.journal_key,
            account_scope=value.h.account,
            source_scope_sha256=source.semantic_sha256,
        ),
    )
    initial = ForwardDataState((source,), "recorded")
    stamp = at.astimezone(ZoneInfo("America/New_York")).strftime("%H:%M:%S %Z %m-%d-%Y")
    publication = capture(
        req,
        initial,
        journal(value.engine),
        value.artifacts,
        clock=Clock(at),
        transport=Transport(
            quote_body(
                dateTimeUTC=int(at.timestamp()),
                All={"bid": 99, "ask": 100, "bidTime": stamp, "askTime": stamp},
            )
        ),
    )
    closure = ContinuousQuoteClosure(
        account_id=value.h.account,
        closure_id="retained-quote-frontier",
        initial_state=initial,
        publications=(publication,),
        selections=(
            ContinuousQuoteSelection(
                publication.record.observations[0].observation_id,
                ForwardRequirement(source.source_id, instrument_id, "SPY", at.date(), "quote"),
                Side.BUY,
                req.producer,
            ),
        ),
        admitted_at=at + timedelta(milliseconds=300),
        boot_id=publication.record.receipt.boot_id,
        admitted_monotonic_ns=1300000000,
        evidence_class="synthetic_fixture",
    )
    yield value, previous, closure
    value.engine.dispose()


def prepare(case, previous, closure):
    resolved = case.forward.resolve(closure)
    frontier = project_continuous_quote_frontier(
        checkpoint=previous.checkpoint, closure=closure, source_state=resolved.state
    )
    transition = case.owner.prepare_frontier(
        command_id=closure.closure_id, checkpoint=previous.checkpoint, frontier=frontier
    )
    prepared = case.store.prepare(
        transition,
        scope=case.scope,
        previous=previous,
        source_evidence=case.put(CONTINUOUS_QUOTE_CLOSURE_SCHEMA, closure),
    )
    return prepared, transition, frontier


def count(case, table):
    with case.engine.connect() as connection:
        return connection.scalar(sa.select(sa.func.count()).select_from(table))


def test_actual_retained_quote_publishes_and_restarts_original_price_times(case):
    owner, previous, closure = case
    prepared, transition, frontier = prepare(owner, previous, closure)
    old_holds = count(owner, daily_runtime_hold_heads)
    with owner.store.write_transaction() as connection:
        receipt = owner.store.commit_in_transaction(
            connection, prepared=prepared, fence=owner.h.lease.fence
        )
    # A later actual capture extends this journal without refreshing the old proof.
    original = closure.publications[0]
    capture(
        replace(original.record.request, capture_id="later-unselected-quote"),
        owner.forward.resolve(closure).state,
        journal(owner.engine),
        owner.artifacts,
        clock=Clock(original.record.receipt.requested_at + timedelta(milliseconds=400)),
        transport=Transport(owner.artifacts.read(original.record.raw_object)),
        head=original.journal_receipt.committed_head,
    )
    owner.store = owner.new_store()
    restarted = owner.store.restore(owner.scope)
    assert receipt.commit.sequence == 2 and restarted.receipt == receipt
    assert restarted.checkpoint == transition.checkpoint
    assert restarted.checkpoint.state.commitments == previous.checkpoint.state.commitments
    assert restarted.checkpoint.state.broker_events == previous.checkpoint.state.broker_events == ()
    assert not transition.new_decisions
    mark = frontier.events[0].payload.payload
    assert mark.price == 100 and mark.basis == "runtime_quote_ask_v1"
    assert mark.knowledge_at == closure.publications[0].record.receipt.validated_at
    assert mark.economic_at == closure.publications[0].record.observations[0].payload.ask_at
    assert frontier.events[0].knowledge_at == closure.admitted_at
    assert count(owner, daily_runtime_hold_heads) == old_holds
    with owner.store.write_transaction() as connection:
        assert (
            owner.store.retry_in_transaction(
                connection,
                original=restarted,
                command_sha256=transition.command_sha256,
                fence=owner.h.lease.fence,
            )
            == receipt
        )
    assert count(owner, continuous_account_commits) == 2


@pytest.mark.parametrize("change", ["scope", "stale", "class"])
def test_changed_quote_scope_freshness_or_class_cannot_publish(case, change):
    owner, previous, closure = case
    prepared, transition, _ = prepare(owner, previous, closure)
    if change == "scope":
        changed = replace(
            closure,
            selections=(
                replace(
                    closure.selections[0],
                    expected=replace(closure.selections[0].expected, symbol="QQQ"),
                ),
            ),
        )
    elif change == "stale":
        changed = replace(closure, admitted_at=closure.admitted_at + timedelta(seconds=1))
    else:
        with pytest.raises(ValueError, match="SCOPE_CLASS"):
            replace(closure, evidence_class="provider_https_read")
        assert count(owner, continuous_account_commits) == 1
        return
    with pytest.raises(ValueError):
        owner.store.prepare(
            transition,
            scope=owner.scope,
            previous=previous,
            source_evidence=owner.put(CONTINUOUS_QUOTE_CLOSURE_SCHEMA, changed),
        )
    assert prepared is not None and count(owner, continuous_account_commits) == 1


def test_quote_final_sql_has_no_codec_object_normalization_or_accounting(case, monkeypatch):
    owner, previous, closure = case
    prepared, _, _ = prepare(owner, previous, closure)

    def forbidden(*args, **kwargs):
        raise AssertionError("HEAVY_QUOTE_WORK_UNDER_SQL")

    for name in ("encode_record", "decode_record"):
        monkeypatch.setattr(codec, name, forbidden)
    for name in ("read", "put"):
        monkeypatch.setattr(owner.artifacts, name, forbidden)
    for name in ("project", "advance"):
        monkeypatch.setattr(PersonalAccounting, name, forbidden)
    monkeypatch.setattr(owner.forward, "_fingerprint", forbidden)
    with owner.store.write_transaction() as connection:
        receipt = owner.store.commit_in_transaction(
            connection, prepared=prepared, fence=owner.h.lease.fence
        )
    assert receipt.commit.sequence == 2


def test_source_tamper_after_quote_preparation_rolls_back_checkpoint(case):
    owner, previous, closure = case
    prepared, _, _ = prepare(owner, previous, closure)
    with owner.engine.begin() as connection:
        connection.execute(
            sa.update(journal_entries)
            .where(
                journal_entries.c.command_id == closure.publications[0].record.request.capture_id
            )
            .values(payload=b"{}")
        )
    with pytest.raises(ValueError), owner.store.write_transaction() as connection:
        owner.store.commit_in_transaction(connection, prepared=prepared, fence=owner.h.lease.fence)
    assert count(owner, continuous_account_commits) == 1


def test_quote_outer_failure_rolls_back_checkpoint_and_original_source_remains(case):
    owner, previous, closure = case
    prepared, _, _ = prepare(owner, previous, closure)
    entries = count(owner, journal_entries)
    with (
        pytest.raises(RuntimeError, match="AFTER_QUOTE_COMMIT"),
        owner.store.write_transaction() as connection,
    ):
        owner.store.commit_in_transaction(connection, prepared=prepared, fence=owner.h.lease.fence)
        raise RuntimeError("AFTER_QUOTE_COMMIT")
    assert count(owner, continuous_account_commits) == 1
    assert count(owner, journal_entries) == entries
    assert owner.forward.resolve(closure).closure == closure
