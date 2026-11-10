"""An actual retained quote prefix keeps its original venue ancestor on restart."""

from dataclasses import replace
from datetime import timedelta
from zoneinfo import ZoneInfo

import pytest

from packages.application.continuous_quote_frontier import project_continuous_quote_frontier
from packages.domain.continuous_composition_contracts import VENUE_CAPTURE_CLOSURE_SCHEMA
from packages.domain.continuous_quote_contracts import (
    CONTINUOUS_QUOTE_CLOSURE_SCHEMA,
    ContinuousQuoteClosure,
    ContinuousQuoteSelection,
)
from packages.domain.forward_contracts import ForwardDataState, ForwardRequirement
from packages.domain.models import Side
from packages.persistence.continuous_account import ContinuousAccountConflict
from tests.integration.test_continuous_reconciliation_publication import PublicationCase
from tests.integration.test_personal_forward_capture_journal import capture, journal
from tests.unit.test_personal_forward_capture import Clock, Transport, quote_body, request


def _publish_quote(case):
    base = case.base
    session = next(
        s
        for s in base.inputs.spec.calendar.sessions
        if s.session_label == base.inputs.spec.window.scored_sessions[0]
    )
    at = session.opens_at
    base.h.coordinator.release(base.h.lease.fence)
    base.h.clock.instant = at + timedelta(milliseconds=300)
    base.h.lease = base.h.coordinator.acquire("owner")
    case.restart()
    previous = case.account.restore(base.scope)
    req = request()
    source = replace(req.source, account_scope=base.h.account)
    instrument_id = base.inputs.spec.instruments[0][0]
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
            account_scope=base.h.account,
            source_scope_sha256=source.semantic_sha256,
        ),
    )
    state = ForwardDataState((source,), "recorded")
    stamp = at.astimezone(ZoneInfo("America/New_York")).strftime("%H:%M:%S %Z %m-%d-%Y")
    publication = capture(
        req,
        state,
        journal(base.engine),
        base.artifacts,
        clock=Clock(at),
        transport=Transport(
            quote_body(
                dateTimeUTC=int(at.timestamp()),
                All={"bid": 99, "ask": 100, "bidTime": stamp, "askTime": stamp},
            )
        ),
    )
    closure = ContinuousQuoteClosure(
        account_id=base.h.account,
        closure_id="quote-after-reconciliation",
        initial_state=state,
        publications=(publication,),
        selections=(
            ContinuousQuoteSelection(
                publication.record.observations[0].observation_id,
                ForwardRequirement(
                    source.source_id, instrument_id, "SPY", session.session_label, "quote"
                ),
                Side.BUY,
                req.producer,
            ),
        ),
        admitted_at=base.h.clock.instant,
        boot_id=publication.record.receipt.boot_id,
        admitted_monotonic_ns=1300000000,
        evidence_class="synthetic_fixture",
    )
    resolved = base.forward.resolve(closure)
    frontier = project_continuous_quote_frontier(
        checkpoint=previous.checkpoint, closure=closure, source_state=resolved.state
    )
    transition = base.owner.prepare_frontier(
        command_id=closure.closure_id, checkpoint=previous.checkpoint, frontier=frontier
    )
    prepared = case.account.prepare(
        transition,
        scope=base.scope,
        previous=previous,
        source_evidence=base.put(CONTINUOUS_QUOTE_CLOSURE_SCHEMA, closure),
    )
    with case.account.write_transaction() as connection:
        case.account.commit_in_transaction(connection, prepared=prepared, fence=base.h.lease.fence)
    return case.account.restore(base.scope)


def test_owned_ancestor_survives_quote_restart_without_refresh_or_recursive_restore(
    tmp_path, monkeypatch
):
    case = PublicationCase(tmp_path)
    try:
        genesis = case.account.restore(case.base.scope)
        assert (
            case.account.nearest_source_ancestor(genesis, schema_id=VENUE_CAPTURE_CLOSURE_SCHEMA)
            is None
        )
        prepared = case.prepare("original-reconciliation")
        case.publisher.publish(prepared, fence=case.base.h.lease.fence)
        original = case.restore()
        quote = _publish_quote(case)
        ancestor = case.account.nearest_source_ancestor(
            quote, schema_id=VENUE_CAPTURE_CLOSURE_SCHEMA
        )
        assert ancestor.receipt == original.continuous.receipt
        assert ancestor.checkpoint == original.continuous.checkpoint
        # The accessor does not promote an older lease/time into current evidence.
        assert (
            ancestor.receipt.fence_reference.fencing_generation
            < quote.receipt.fence_reference.fencing_generation
        )
        case.restart()
        restored = case.account.restore(case.base.scope)

        def forbidden(*args, **kwargs):
            raise AssertionError("ancestor lookup performed a recursive restore or SQL read")

        monkeypatch.setattr(case.account, "restore", forbidden)
        monkeypatch.setattr(case.base.engine, "connect", forbidden)
        retained = case.account.nearest_source_ancestor(
            restored, schema_id=VENUE_CAPTURE_CLOSURE_SCHEMA
        )
        assert retained.receipt == original.continuous.receipt
        assert (
            case.account.nearest_source_ancestor(retained, schema_id=VENUE_CAPTURE_CLOSURE_SCHEMA)
            is retained
        )
        with pytest.raises(ContinuousAccountConflict):
            case.account.nearest_source_ancestor(
                replace(restored), schema_id=VENUE_CAPTURE_CLOSURE_SCHEMA
            )
        assert (
            case.account.nearest_source_ancestor(
                restored, schema_id=CONTINUOUS_QUOTE_CLOSURE_SCHEMA
            )
            is restored
        )
        assert (
            case.account.nearest_source_ancestor(
                retained, schema_id=CONTINUOUS_QUOTE_CLOSURE_SCHEMA
            )
            is None
        )
        with pytest.raises(ContinuousAccountConflict):
            case.account.nearest_source_ancestor(
                replace(restored), schema_id=CONTINUOUS_QUOTE_CLOSURE_SCHEMA
            )
        with pytest.raises(ContinuousAccountConflict, match="ANCESTOR_SCHEMA"):
            case.account.nearest_source_ancestor(restored, schema_id="unsupported-source-schema/1")
    finally:
        case.close()
