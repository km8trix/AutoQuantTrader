"""Actual independent venue fill -> sole engine -> atomic C/B/A publication.

The initial risk approval and modeled venue delivery use labelled fixtures. All
observed source, canonical parent, hold revisions and applied publication below
use their concrete owners; no fixture parent or observed source table is used.
"""

from datetime import timedelta
from decimal import Decimal

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.application.continuous_reconciliation import (
    ContinuousReconciliationTransitionResolver,
)
from packages.application.continuous_venue_frontier import project_continuous_venue_frontier
from packages.application.venue_reconciliation import VenueReconciliationResolver
from packages.domain.continuous_composition_contracts import VENUE_CAPTURE_CLOSURE_SCHEMA
from packages.domain.continuous_persistence_contracts import (
    CONTINUOUS_COMMIT_SCHEMA,
    ContinuousAccountCommit,
)
from packages.domain.venue_reconciliation_contracts import VenueCaptureRequest
from packages.persistence.applied_reconciliation_schema import applied_reconciliation_commits
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_observed_hold_sources import SqlContinuousObservedHoldSources
from packages.persistence.continuous_reconciliation_publication import (
    SqlContinuousReconciliationPublication,
)
from packages.persistence.continuous_venue_sources import SqlContinuousVenueSources
from packages.persistence.daily_runtime_risk_schema import (
    DAILY_RUNTIME_TABLES,
    daily_runtime_hold_events,
)
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
from tests.integration.test_daily_observed_holds import ObservedCase
from tests.integration.test_venue_reconciliation_capture import Clock


class ObservedDelegate:
    def __init__(self, original):
        self.original = original
        self.observed = None

    def __getattr__(self, name):
        if "observed_hold_source" in name:
            assert self.observed is not None
            return getattr(self.observed, name)
        return getattr(self.original, name)


class CoupledCase:
    def __init__(self, path):
        self.venue_case = ObservedCase(path)
        self.base = self.venue_case.base
        self.h = self.base.h
        self.restart()

    def restart(self):
        b, h, c = self.base, self.h, self.venue_case
        delegate = ObservedDelegate(b.reader)
        h.store.producers = delegate
        self.sources = SqlContinuousVenueSources(
            b.engine,
            artifacts=b.artifacts,
            codec=codec,
            resolver=VenueReconciliationResolver(
                transition_resolver=ContinuousReconciliationTransitionResolver(
                    accounting=c.accounting
                )
            ),
            scope=c.scope,
            model=c.model,
        )
        self.composer = SqlContinuousCommitComposer(
            b.engine,
            daily=h.store,
            coordinator=h.coordinator,
            forward_sources=b.forward,
            artifacts=b.artifacts,
            codec=codec,
            producer_history=delegate,
            fence=h.lease.fence,
            benchmark_instrument_id=b.inputs.spec.instruments[0][0],
            venue_sources=self.sources,
            accounting=c.accounting,
        )
        self.account = SqlContinuousAccount(
            b.engine,
            coordinator=h.coordinator,
            journal=SqlDurableJournal(
                b.engine,
                codec=codec,
                record_types={CONTINUOUS_COMMIT_SCHEMA: ContinuousAccountCommit},
            ),
            artifacts=b.artifacts,
            codec=codec,
            preparer=b.owner,
            composer=self.composer,
        )
        self.observed = SqlContinuousObservedHoldSources(
            b.engine,
            accounts=self.account,
            preparer=b.owner,
            venue_sources=self.sources,
            daily=h.store,
            artifacts=b.artifacts,
            codec=codec,
        )
        delegate.observed = self.observed
        self.publisher = SqlContinuousReconciliationPublication(
            b.engine,
            account=self.account,
            composer=self.composer,
            coordinator=h.coordinator,
            sources=self.sources,
            artifacts=b.artifacts,
            codec=codec,
            accounting=c.accounting,
        )

    def prepare(self, identity="partial"):
        c, b, h = self.venue_case, self.base, self.h
        venue = c.venue.read()
        at = max(venue.state.as_of + timedelta(seconds=3), h.clock.instant + timedelta(seconds=2))
        if at >= h.lease.expires_at:
            h.coordinator.release(h.lease.fence)
            h.clock.instant = at
            h.lease = h.coordinator.acquire("owner")
            self.restart()
        else:
            h.clock.instant = at
        previous = self.account.restore(b.scope)
        assert previous is not None
        prior = self.publisher.restore(c.scope, account_scope=b.scope)
        capture = SqlVenueReconciliationCapture(
            b.engine,
            artifacts=b.artifacts,
            codec=codec,
            clock=Clock(at - timedelta(seconds=1)),
        ).capture(
            VenueCaptureRequest(
                identity, c.binding, b.inputs.spec.initialized_at, venue.state.as_of
            ),
            venue=c.venue,
        )
        applications = (
            c.applications
            if prior is None
            else prior.reconciliation.resolved.applications.applications
        )
        frontier = project_continuous_venue_frontier(
            checkpoint=previous.checkpoint,
            capture=capture,
            prior_applications=applications,
            frontier_id=identity,
            admitted_at=at,
        )
        transition = b.owner.prepare_frontier(
            command_id=identity, checkpoint=previous.checkpoint, frontier=frontier
        )
        token = self.observed.retain_source(
            previous=previous,
            transition=transition,
            venue=self.sources.resolve(capture),
            current=h.resolved(),
        )
        current = h.store.resolve_snapshot(
            h.store.read_observed_hold_snapshot(
                account_id=h.account, fence=h.lease.fence, source_ref=token.reference
            )
        )
        holds = h.store.prepare_observed_holds(current)
        canonical = self.account.prepare(
            transition,
            scope=b.scope,
            previous=previous,
            source_evidence=b.put(VENUE_CAPTURE_CLOSURE_SCHEMA, capture),
            observed_holds=holds,
        )
        prepared = self.publisher.prepare(canonical, previous=prior)
        return token, holds, prepared

    def restore(self):
        return self.publisher.restore(self.venue_case.scope, account_scope=self.base.scope)

    def counts(self):
        with self.base.engine.connect() as connection:
            return tuple(
                connection.scalar(sa.select(sa.func.count()).select_from(table))
                for table in (
                    continuous_account_commits,
                    applied_reconciliation_commits,
                    journal_entries,
                    *DAILY_RUNTIME_TABLES,
                )
            )


@pytest.fixture
def coupled(tmp_path):
    case = CoupledCase(tmp_path)
    try:
        yield case
    finally:
        case.venue_case.close()


def test_actual_partial_fill_publishes_c_b_a_and_restarts(coupled):
    c = coupled
    c.venue_case.fill("1")
    token, holds, prepared = c.prepare()
    before = holds.result.before.bindings[0].commitment
    after = holds.result.after.bindings[0].commitment
    assert after.remaining_quantity == before.remaining_quantity - Decimal(1)
    assert after.reserved_cash < before.reserved_cash
    receipt = c.publisher.publish(prepared, fence=c.h.lease.fence)
    assert (
        receipt.continuous.commit.transition.resulting_heads.capacity_sha256
        == holds.result.after.semantic_sha256
    )
    assert receipt.continuous.commit.sequence == holds.result.group.coordinator_sequence
    assert (
        token.inputs.resulting.state
        == prepared.continuous.composition.state.observed_holds.snapshot.observed_sources.inputs[
            0
        ].resulting.state
    )
    c.restart()
    restored = c.restore()
    assert restored.continuous.receipt == receipt.continuous
    assert restored.continuous.checkpoint == token.inputs.resulting
    assert c.h.resolved().obligations == holds.result.after
    assert c.h.resolved().attempts == ()
    assert (
        restored.reconciliation.resolved.commit.resulting_heads
        == receipt.continuous.commit.transition.resulting_heads
    )
    counts = c.counts()
    assert c.publisher.retry(restored, fence=c.h.lease.fence) == receipt
    assert c.counts() == counts


def test_applied_write_failure_rolls_back_all_c_b_financial_writes(coupled, monkeypatch):
    c = coupled
    c.venue_case.fill("1")
    token, holds, prepared = c.prepare()
    before = c.counts()

    def fail(*args, **kwargs):
        raise RuntimeError("injected applied publication fault")

    monkeypatch.setattr(c.publisher.applied, "commit_in_transaction", fail)
    with pytest.raises(RuntimeError, match="injected"):
        c.publisher.publish(prepared, fence=c.h.lease.fence)
    assert c.counts() == before
    assert c.h.resolved().obligations == holds.result.before
    assert c.account.restore(c.base.scope).checkpoint == token.inputs.previous


def test_overlap_then_full_fill_preserves_original_hold_history(coupled):
    c = coupled
    c.venue_case.fill("1")
    token, first, prepared = c.prepare()
    c.publisher.publish(prepared, fence=c.h.lease.fence)
    c.restart()
    _, repeated, overlap = c.prepare("overlap")
    assert repeated.result.group is None
    assert repeated.result.before == repeated.result.after == first.result.after
    c.publisher.publish(overlap, fence=c.h.lease.fence)
    assert (
        c.restore().continuous.receipt.commit.transition.resulting_heads.effect_watermark
        == first.result.coordinator_sequence
    )
    remaining = first.result.after.bindings[0].commitment.remaining_quantity
    c.venue_case.fill(str(remaining))
    terminal_token, _terminal, completed = c.prepare("complete")
    c.publisher.publish(completed, fence=c.h.lease.fence)
    c.restart()
    restored = c.restore()
    final_hold = c.h.resolved().obligations.bindings[0].commitment
    assert final_hold.state == "terminal"
    assert final_hold.remaining_quantity == final_hold.reserved_cash == 0
    assert len(c.h.resolved().observed_groups) == 2
    assert restored.continuous.checkpoint.state == terminal_token.inputs.resulting.state
    old = c.publisher.restore(c.venue_case.scope, account_scope=c.base.scope, command_id="partial")
    assert old.continuous.checkpoint == token.inputs.resulting
    assert (
        old.continuous.receipt.commit.transition.resulting_heads.capacity_sha256
        == first.result.after.semantic_sha256
    )


@pytest.mark.parametrize("target", ["hold", "applied", "journal"])
def test_late_mutation_after_applied_write_rolls_back_every_participant(
    coupled, monkeypatch, target
):
    c = coupled
    c.venue_case.fill("1")
    _, holds, prepared = c.prepare()
    before = c.counts()
    original = c.publisher.applied.commit_in_transaction

    def mutate(connection, **kwargs):
        receipt = original(connection, **kwargs)
        if target == "hold":
            query = (
                sa.update(daily_runtime_hold_events)
                .where(daily_runtime_hold_events.c.revision > 1)
                .values(payload=b"changed")
            )
        elif target == "applied":
            query = (
                sa.update(applied_reconciliation_commits)
                .where(applied_reconciliation_commits.c.command_id == "partial")
                .values(canonical_payload=b"changed")
            )
        else:
            query = (
                sa.update(journal_entries)
                .where(
                    journal_entries.c.key_sha256
                    == prepared.reconciliation.receipt.journal_key.semantic_sha256
                )
                .values(payload=b"changed")
            )
        assert connection.execute(query).rowcount == 1
        return receipt

    monkeypatch.setattr(c.publisher.applied, "commit_in_transaction", mutate)
    with pytest.raises(ValueError):
        c.publisher.publish(prepared, fence=c.h.lease.fence)
    assert c.counts() == before
    assert c.h.resolved().obligations == holds.result.before


def test_actual_observed_publication_has_no_codec_object_io_or_replay_under_sql(
    coupled, monkeypatch
):
    c = coupled
    c.venue_case.fill("1")
    _, _, prepared = c.prepare()
    # Public full-content validation happens before entering the write boundary.
    c.publisher.require_prepared(prepared)
    original = c.account.write_transaction
    from contextlib import contextmanager

    def blocked(*args, **kwargs):
        raise AssertionError("heavy work under account SQL")

    @contextmanager
    def guarded():
        with original() as connection, monkeypatch.context() as patch:
            patch.setattr(codec, "encode_record", blocked)
            patch.setattr(codec, "decode_record", blocked)
            patch.setattr(c.base.artifacts, "read", blocked)
            patch.setattr(c.base.artifacts, "put", blocked)
            patch.setattr(c.base.owner, "prepare_frontier", blocked)
            yield connection

    monkeypatch.setattr(c.account, "write_transaction", guarded)
    c.publisher.publish(prepared, fence=c.h.lease.fence)
