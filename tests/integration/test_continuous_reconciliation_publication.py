"""Independent SQLite venue → actual sole engine → atomic C/A evidence stores."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest
import sqlalchemy as sa

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.application.continuous_reconciliation import (
    ContinuousReconciliationTransitionResolver,
)
from packages.application.continuous_venue_frontier import (
    continuous_initial_cash_application,
    project_continuous_venue_frontier,
)
from packages.application.venue_reconciliation import VenueReconciliationResolver
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.continuous_composition_contracts import VENUE_CAPTURE_CLOSURE_SCHEMA
from packages.domain.continuous_persistence_contracts import (
    CONTINUOUS_COMMIT_SCHEMA,
    ContinuousAccountCommit,
)
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.personal_contracts import content_digest
from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.domain.stateful_venue_contracts import VenueCommand
from packages.domain.venue_reconciliation_contracts import VenueAccountBinding, VenueCaptureRequest
from packages.persistence.applied_reconciliation_schema import applied_reconciliation_commits
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_reconciliation_publication import (
    SqlContinuousReconciliationPublication,
)
from packages.persistence.continuous_venue_sources import SqlContinuousVenueSources
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.schema import metadata
from packages.persistence.stateful_venue import SqlStatefulVenue
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
from tests.integration.test_continuous_composition import Case
from tests.integration.test_venue_reconciliation_capture import Clock
from tests.unit.test_stateful_venue import FixtureVerifier, model


class PublicationCase:
    def __init__(self, path):
        self.base = Case(path, captured=False)
        self.base.publish()
        checkpoint = self.base.first.checkpoint
        self.accounting = PersonalAccounting()
        self.model = model(
            initial_cash_flow=checkpoint.state.cash_flows[0],
            instruments=checkpoint.inputs.spec.instruments,
            execution_policy=replace(
                checkpoint.inputs.spec.execution_policy, model_id="stateful-venue-facts-v1"
            ),
        )
        self.venue_engine = create_database_engine(f"sqlite+pysqlite:///{path}/independent.sqlite")
        metadata.create_all(self.venue_engine, tables=JOURNAL_TABLES)
        self.venue = SqlStatefulVenue(
            self.venue_engine,
            model=self.model,
            artifacts=LocalResearchArtifactStore(path / "independent-objects"),
            codec=codec,
            verified_sources=FixtureVerifier(),
            accounting=self.accounting,
        )
        self.venue.initialize()
        self.scope = ReconciliationScope(
            checkpoint.inputs.spec.account_id,
            self.model.venue_id,
            "stateful_simulation",
            checkpoint.inputs.spec.account_binding_sha256,
            "stateful_simulation",
        )
        self.binding = VenueAccountBinding(self.scope, self.model, content_digest(self.model), ())
        self.restart()

    def restart(self):
        b = self.base
        self.sources = SqlContinuousVenueSources(
            b.engine,
            artifacts=b.artifacts,
            codec=codec,
            resolver=VenueReconciliationResolver(
                transition_resolver=ContinuousReconciliationTransitionResolver(
                    accounting=self.accounting
                )
            ),
            scope=self.scope,
            model=self.model,
        )
        self.composer = SqlContinuousCommitComposer(
            b.engine,
            daily=b.h.store,
            coordinator=b.h.coordinator,
            forward_sources=b.forward,
            artifacts=b.artifacts,
            codec=codec,
            producer_history=b.reader,
            fence=b.h.lease.fence,
            benchmark_instrument_id=b.inputs.spec.instruments[0][0],
            venue_sources=self.sources,
            accounting=self.accounting,
        )
        self.account = SqlContinuousAccount(
            b.engine,
            coordinator=b.h.coordinator,
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
        self.publisher = SqlContinuousReconciliationPublication(
            b.engine,
            account=self.account,
            composer=self.composer,
            coordinator=b.h.coordinator,
            sources=self.sources,
            artifacts=b.artifacts,
            codec=codec,
            accounting=self.accounting,
        )

    def prepare(self, name, *, previous=None, capture=None):
        b = self.base
        current = self.account.restore(b.scope)
        assert current is not None
        if capture is None:
            venue = self.venue.read()
            observed_at = max(current.checkpoint.now, venue.state.as_of) + timedelta(seconds=1)
            capture = SqlVenueReconciliationCapture(
                b.engine, artifacts=b.artifacts, codec=codec, clock=Clock(observed_at)
            ).capture(
                VenueCaptureRequest(
                    name, self.binding, b.inputs.spec.initialized_at, venue.state.as_of
                ),
                venue=self.venue,
            )
        applications = (
            (continuous_initial_cash_application(current.checkpoint, accounting=self.accounting),)
            if previous is None
            else previous.reconciliation.resolved.applications.applications
        )
        frontier = project_continuous_venue_frontier(
            checkpoint=current.checkpoint,
            capture=capture,
            prior_applications=applications,
            frontier_id=name,
            admitted_at=max(current.checkpoint.now, capture.observed.completed_at)
            + timedelta(seconds=1),
        )
        transition = b.owner.prepare_frontier(
            command_id=name, checkpoint=current.checkpoint, frontier=frontier
        )
        b.h.clock.instant = frontier.knowledge_at
        ref = b.put(VENUE_CAPTURE_CLOSURE_SCHEMA, capture)
        canonical = self.account.prepare(
            transition, scope=b.scope, previous=current, source_evidence=ref
        )
        return self.publisher.prepare(canonical, previous=previous)

    def restore(self, command=None):
        return self.publisher.restore(self.scope, account_scope=self.base.scope, command_id=command)

    def counts(self):
        with self.base.engine.connect() as connection:
            return tuple(
                connection.scalar(sa.select(sa.func.count()).select_from(table))
                for table in (
                    continuous_account_commits,
                    applied_reconciliation_commits,
                    journal_entries,
                )
            )

    def close(self):
        self.base.engine.dispose()
        self.venue_engine.dispose()


@pytest.fixture
def case(tmp_path):
    value = PublicationCase(tmp_path)
    try:
        yield value
    finally:
        value.close()


def test_actual_genesis_round_repeated_convergence_and_original_retry(case):
    prepared = case.prepare("first-observation")
    binding = prepared.reconciliation.resolved.commit.capture_binding
    assert binding.source_closure_sha256 != binding.manifest_sha256
    assert binding.capture.object_ref in prepared.reconciliation.resolved.retained_objects
    receipt = case.publisher.publish(prepared, fence=case.base.h.lease.fence)
    assert (
        receipt.reconciliation.commit.canonical_transition_ref
        == receipt.continuous.commit.transition
    )
    first = case.restore()
    assert first.reconciliation.resolved.result.status == "blocked"
    assert first.reconciliation.resolved.result.blocking_reasons == ("CONVERGENCE_ROUND_REQUIRED",)
    assert len(first.reconciliation.resolved.applications.applications) == 1
    assert first.continuous.checkpoint.current.snapshot.trade_date_cash == Decimal(10000)
    initial_time = first.reconciliation.resolved.applications.applications[0].applied_at
    case.restart()
    original = case.restore("first-observation")
    second = case.prepare("second-observation", previous=original)
    case.publisher.publish(second, fence=case.base.h.lease.fence)
    restored = case.restore()
    assert restored.reconciliation.resolved.result.status == "converged"
    assert restored.reconciliation.resolved.applications.applications[0].applied_at == initial_time
    before = case.counts()
    retried = case.publisher.retry(original, fence=case.base.h.lease.fence)
    assert retried == receipt
    assert case.counts() == before


def test_actual_external_cash_applies_once_and_retains_owner_barrier(case):
    at = case.base.first.checkpoint.now + timedelta(seconds=1)
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(500),
        effective_at=at,
        recorded_at=at,
        external_reference="external-cash",
    )
    case.venue.execute(VenueCommand("external-cash", at, flow))
    first = case.prepare("cash-observation")
    case.publisher.publish(first, fence=case.base.h.lease.fence)
    original = case.restore()
    assert original.continuous.checkpoint.current.snapshot.trade_date_cash == Decimal(10500)
    assert original.continuous.checkpoint.state.halted
    assert original.reconciliation.resolved.result.status == "blocked"
    assert original.reconciliation.resolved.applications.applied_through == at
    timestamp = next(
        a.applied_at
        for a in original.reconciliation.resolved.applications.applications
        if a.fact_id == flow.cash_flow_id
    )
    second = case.prepare("cash-overlap", previous=original)
    case.publisher.publish(second, fence=case.base.h.lease.fence)
    repeated = case.restore()
    assert repeated.continuous.checkpoint.current.snapshot.trade_date_cash == Decimal(10500)
    assert (
        next(
            a.applied_at
            for a in repeated.reconciliation.resolved.applications.applications
            if a.fact_id == flow.cash_flow_id
        )
        == timestamp
    )
    assert len(repeated.continuous.checkpoint.flows) == 2


def test_final_sql_has_no_codec_objects_accounting_or_independent_queries(case, monkeypatch):
    prepared = case.prepare("no-heavy-sql")
    active = set()
    engine = case.base.engine
    hooks = (
        ("begin", lambda connection: active.add(id(connection))),
        ("commit", lambda connection: active.discard(id(connection))),
        ("rollback", lambda connection: active.discard(id(connection))),
    )
    for event, hook in hooks:
        sa.event.listen(engine, event, hook)

    def guarded(original):
        def checked(*args, **kwargs):
            assert not active, "heavy work under account transaction"
            return original(*args, **kwargs)

        return checked

    for target, names in (
        (codec, ("encode_record", "decode_record")),
        (case.base.artifacts, ("read", "put")),
        (case.accounting, ("advance", "project")),
        (case.venue, ("read", "facts")),
    ):
        for name in names:
            monkeypatch.setattr(target, name, guarded(getattr(target, name)))
    try:
        case.publisher.publish(prepared, fence=case.base.h.lease.fence)
        original = case.restore()
        case.publisher.require_resolved(original)
        with case.account.write_transaction() as connection:
            observed = case.publisher.recheck_in_transaction(
                connection, original, fence=case.base.h.lease.fence, require_current=True
            )
        assert observed.current_heads == original.reconciliation.resolved.result.heads
    finally:
        for event, hook in hooks:
            sa.event.remove(engine, event, hook)


@pytest.mark.parametrize("failure", ("before-a", "after-a", "after-a-deadline"))
def test_late_failure_rolls_back_actual_c_and_a_as_one_operation(case, monkeypatch, failure):
    prepared = case.prepare("atomic-failure")
    before = case.counts()
    original = case.publisher.applied.commit_in_transaction

    def fail(connection, **kwargs):
        # C is already visible to this exact transaction, but not committed.
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(continuous_account_commits))
            == before[0] + 1
        )
        if failure == "before-a":
            raise ValueError("synthetic-late-failure")
        value = original(connection, **kwargs)
        if failure == "after-a":
            raise ValueError("synthetic-late-failure")
        case.base.h.clock.instant = case.base.h.lease.expires_at
        return value

    monkeypatch.setattr(case.publisher.applied, "commit_in_transaction", fail)
    with pytest.raises((ValueError, RuntimeError)):
        case.publisher.publish(prepared, fence=case.base.h.lease.fence)
    assert case.counts() == before


def test_caller_constructed_passing_evidence_cannot_replace_actual_capture(case, monkeypatch):
    at = case.base.first.checkpoint.now + timedelta(seconds=1)
    cash = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(100),
        effective_at=at,
        recorded_at=at,
        external_reference="forgery-oracle-cash",
    )
    case.venue.execute(VenueCommand("fixture-cash", at, cash))
    prepared = case.prepare("forged-source")
    capture = prepared.view.venue.capture
    forged = replace(capture, source_order=tuple(reversed(capture.source_order)))
    from packages.domain.reconciliation_persistence_contracts import ReconciliationEvidenceRef

    forged_ref = case.base.put(VENUE_CAPTURE_CLOSURE_SCHEMA, forged)
    commit = prepared.reconciliation.resolved.commit
    forged_commit = replace(
        commit,
        capture_binding=replace(
            commit.capture_binding,
            capture=ReconciliationEvidenceRef(
                forged_ref.schema_id, forged_ref.object_ref, forged_ref.semantic_sha256
            ),
        ),
    )
    # A generic pure DTO/evidence match is deliberately not durable authority.
    structural = case.publisher.evidence.resolve(forged_commit)
    assert structural.sources == capture.manifest
    fake = case.publisher.applied.prepare(
        forged_commit, expected_head=prepared.journal.head, previous=None
    )
    before = case.counts()
    with pytest.raises(ValueError, match=r"OWNED_PUBLICATION|TOKEN_CHANGED"):
        case.publisher.publish(
            replace(prepared, reconciliation=fake), fence=case.base.h.lease.fence
        )
    # Even direct C→generic-A calls cannot acquire the concrete reader's context.
    with (
        pytest.raises(ValueError, match="OWNED_ACTIVE_ACCOUNT_PUBLICATION_REQUIRED"),
        case.account.write_transaction() as connection,
    ):
        case.account.commit_in_transaction(
            connection, prepared=prepared.continuous, fence=case.base.h.lease.fence
        )
        case.publisher.applied.commit_in_transaction(
            connection, prepared=fake, fence=case.base.h.lease.fence
        )
    assert case.counts() == before


def test_original_source_deletion_blocks_final_publication(case):
    prepared = case.prepare("deleted-original")
    source = prepared.view.venue.capture.manifest.sources[0]
    with case.base.engine.begin() as connection:
        connection.execute(
            sa.delete(journal_entries).where(journal_entries.c.record_id == source.record_id)
        )
    before = case.counts()
    with pytest.raises(ValueError):
        case.publisher.publish(prepared, fence=case.base.h.lease.fence)
    assert case.counts() == before


def test_altered_original_application_time_and_nested_view_mutation_reject(case):
    from packages.application.continuous_reconciliation_publication import (
        validate_continuous_application_times,
    )

    prepared = case.prepare("original-time")
    app = prepared.view.evidence.applications[0]
    with pytest.raises(ValueError, match="INITIAL_APPLICATION"):
        validate_continuous_application_times(
            case.publisher._checkpoint(prepared.continuous),
            capture=prepared.view.venue.capture,
            applications=(replace(app, applied_at=app.applied_at + timedelta(microseconds=1)),),
            accounting=case.accounting,
        )
    before = case.counts()
    original = prepared.reconciliation.resolved.result.completed_at
    object.__setattr__(
        prepared.reconciliation.resolved.result,
        "completed_at",
        original + timedelta(microseconds=1),
    )
    with pytest.raises(ValueError, match="ORIGINAL_PUBLICATION_CONTENT_CHANGED"):
        case.publisher.publish(prepared, fence=case.base.h.lease.fence)
    assert case.counts() == before


def test_exact_prefix_role_resolution_does_not_restore_account_recursively(case, monkeypatch):
    prepared = case.prepare("producer-role")
    case.publisher.publish(prepared, fence=case.base.h.lease.fence)
    current = case.account.restore(case.base.scope)
    monkeypatch.setattr(
        case.account, "restore", lambda *a, **kw: pytest.fail("recursive account restore")
    )
    role = case.publisher.resolve_for_account(current, scope=case.scope)
    assert role.continuous is current
    assert (
        role.reconciliation.resolved.result.heads
        == current.receipt.commit.transition.resulting_heads
    )
    assert role.sources.pages[0].request.binding.model == case.model


def test_unmapped_independent_order_and_successful_cash_publish_null_watermark(case):
    from packages.domain.risk import intent_payload_hash
    from packages.domain.stateful_venue_contracts import VenueAccept
    from tests.unit.test_stateful_venue import SOURCE_BYTES, packet

    for payload in SOURCE_BYTES.values():
        case.venue.artifacts.put(payload)
    at = case.base.first.checkpoint.now + timedelta(seconds=1)
    outgoing = packet(case.model)
    instrument, symbol = case.model.instruments[0]
    expires = at + timedelta(seconds=40)
    old = outgoing.registration
    intent = replace(
        old.submission.intent,
        instrument_id=instrument,
        symbol=symbol,
        created_at=at,
        decision_event_time=at,
        expires_at=expires,
        decision_trigger=replace(old.submission.intent.decision_trigger, as_of=at),
    )
    submission = replace(
        old.submission,
        intent=intent,
        intent_payload_sha256=intent_payload_hash(intent),
        submitted_at=at,
    )
    commitment = replace(
        old.source_commitment,
        instrument_id=instrument,
        symbol=symbol,
        not_before=at,
        expires_at=expires,
    )
    outgoing = replace(
        outgoing, registration=replace(old, submission=submission, source_commitment=commitment)
    )
    ack = case.venue.execute(VenueCommand("unmapped-registration", at, outgoing))
    assert ack.acknowledgment.disposition == "registered"
    at += timedelta(seconds=1)
    case.venue.execute(VenueCommand("unmapped-accept", at, VenueAccept(submission.order_id)))
    at += timedelta(seconds=1)
    cash = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(300),
        effective_at=at,
        recorded_at=at,
        external_reference="independent-valid-cash",
    )
    case.venue.execute(VenueCommand("valid-cash", at, cash))
    prepared = case.prepare("blocked-order-valid-cash")
    case.publisher.publish(prepared, fence=case.base.h.lease.fence)
    restored = case.restore()
    assert restored.continuous.checkpoint.current.snapshot.trade_date_cash == Decimal(10300)
    assert restored.continuous.checkpoint.state.commitments == ()
    assert restored.reconciliation.resolved.applications.applied_through is None
    assert restored.reconciliation.resolved.result.status == "blocked"
    assert (
        restored.reconciliation.resolved.result.unresolved_fact_ids
        or restored.reconciliation.resolved.result.quarantined_fact_ids
    )
    assert cash.cash_flow_id in restored.reconciliation.resolved.result.applied_fact_ids
    case.restart()
    assert case.restore().reconciliation.resolved == restored.reconciliation.resolved


def test_nonbroker_original_time_requires_exact_retained_stage_one_trace(case):
    from packages.application.continuous_reconciliation_publication import (
        validate_continuous_application_times,
    )

    at = case.base.first.checkpoint.now + timedelta(seconds=1)
    cash = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(1),
        effective_at=at,
        recorded_at=at,
        external_reference="timing-oracle",
    )
    case.venue.execute(VenueCommand("timing-oracle", at, cash))
    prepared = case.prepare("original-nonbroker-time")
    apps = prepared.view.evidence.applications
    original = next(value for value in apps if value.fact_id == cash.cash_flow_id)
    changed = replace(original, applied_at=original.applied_at - timedelta(microseconds=1))
    assert cash.recorded_at < changed.applied_at < original.applied_at
    with pytest.raises(ValueError, match="ORIGINAL_APPLICATION_TRACE_DIFFERS"):
        validate_continuous_application_times(
            case.publisher._checkpoint(prepared.continuous),
            capture=prepared.view.venue.capture,
            applications=tuple(changed if value is original else value for value in apps),
            accounting=case.accounting,
        )
    with pytest.raises(ValueError, match="bindings differ"):
        replace(prepared.reconciliation.resolved.commit, capture_binding=None)
