"""Actual venue/sole-engine economics with a labelled fixture source/relational parent.

This tests B's actual store, not the unfinished production C/A source composer.
"""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

import pytest
import sqlalchemy as sa

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.application.continuous_venue_frontier import (
    continuous_initial_cash_application,
    project_continuous_venue_frontier,
)
from packages.application.stateful_venue import venue_order_id
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.accounting_contracts import RegisterVenueSubmission
from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
from packages.domain.daily_attempt import daily_fence_reference
from packages.domain.daily_observed_hold_contracts import (
    RuntimeObservedHoldInputs,
    RuntimeObservedHoldSource,
    daily_runtime_effect_watermark,
)
from packages.domain.personal_contracts import content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads, ReconciliationScope
from packages.domain.stateful_venue_contracts import (
    VenueAccept,
    VenueCancel,
    VenueCommand,
    VenueCorrect,
    VenueSubmit,
)
from packages.domain.venue_reconciliation_contracts import (
    VenueAccountBinding,
    VenueCaptureRequest,
    VenueSubmissionBinding,
)
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.daily_runtime_risk import (
    DailyRuntimeRiskConflict,
    ResolvedRuntimeObservedHoldSources,
    RuntimeObservedHoldSourcePlan,
    RuntimeObservedHoldSourceSnapshot,
    capture_runtime_table,
    daily_attempt_inventory_sha256,
)
from packages.persistence.daily_runtime_risk_schema import (
    DAILY_RUNTIME_TABLES,
    daily_runtime_observed_hold_groups,
)
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.schema import metadata
from packages.persistence.stateful_venue import SqlStatefulVenue
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
from tests.integration.test_continuous_composition import Case
from tests.integration.test_sql_daily_runtime_risk import _write_transaction, prepare_parent_fixture
from tests.integration.test_venue_reconciliation_capture import Clock
from tests.unit.test_stateful_venue import (
    DISPATCH,
    RISK,
    SOURCE_BYTES,
    FixtureVerifier,
    model,
    quote,
    reference,
)

D = Decimal
fixture_sources = sa.Table(
    "fixture_observed_sources",
    sa.MetaData(),
    sa.Column("account_id", sa.String(128), primary_key=True),
    sa.Column("source_id", sa.String(64), primary_key=True),
    sa.Column("payload", sa.LargeBinary, nullable=False),
)


class FixtureObservedReader:
    """Test-only retained bytes + actual sole-engine replay, never runtime qualification."""

    def __init__(self, case, delegate):
        self.case, self.delegate = case, delegate
        self.plans, self.raws = {}, {}

    def __getattr__(self, name):
        return getattr(self.delegate, name)

    def prepare_observed_hold_source_read(self, references):
        plan = RuntimeObservedHoldSourcePlan(references, object())
        self.plans[id(plan)] = plan
        return plan

    def capture_observed_hold_sources_in_transaction(self, connection, plan, *, account_id, budget):
        assert self.plans[id(plan)] is plan
        table = capture_runtime_table(
            connection, fixture_sources, account_id=account_id, budget=budget
        )
        raw = RuntimeObservedHoldSourceSnapshot(plan, (table,), object())
        self.raws[id(raw)] = raw
        return raw

    def resolve_observed_hold_sources(self, snapshot, *, admissions):
        assert self.raws[id(snapshot)] is snapshot
        values = {
            row["source_id"]: codec.decode_record(row["payload"], RuntimeObservedHoldInputs)
            for row in snapshot.tables[0].rows
        }
        selected = tuple(values[ref.semantic_sha256] for ref in snapshot.plan.references)
        for item in selected:
            prepared = self.case.base.owner.prepare_frontier(
                command_id=item.source.coordinator_command_id,
                checkpoint=item.previous,
                frontier=item.frontier,
            )
            # Wall consumption is an original operational observation, not a
            # deterministic economic replay value. Preserve its retained bytes.
            assert (
                0
                <= item.resulting.remaining_wall_nanoseconds
                <= item.resulting.inputs.spec.max_wall_seconds * 10**9
            )
            assert (
                replace(
                    prepared.checkpoint,
                    remaining_wall_nanoseconds=item.resulting.remaining_wall_nanoseconds,
                )
                == item.resulting
            )
            assert prepared.application_batches == item.application_batches
        return ResolvedRuntimeObservedHoldSources(snapshot, selected, object())

    def recheck_observed_hold_sources_in_transaction(self, connection, resolved):
        assert self.raws[id(resolved.snapshot)] is resolved.snapshot
        # B already checks all exact captured row bytes under the caller lock.


class ObservedCase:
    def __init__(self, path, *, two=False):
        if two:
            from tests.unit.test_continuous_engine import inputs_and_prices

            inputs, prices = inputs_and_prices()
            # Keep the existing fixture's explicitly selected SPY benchmark first;
            # the second fixture identity still maps to the supported QQQ symbol.
            extras = tuple(
                replace(
                    event,
                    event_id="second-" + event.event_id,
                    payload=replace(event.payload, instrument_id="ZZ-FIXTURE-QQQ", symbol="QQQ"),
                    provenance=replace(
                        event.provenance,
                        normalized_sha256=content_digest(
                            replace(event.payload, instrument_id="ZZ-FIXTURE-QQQ", symbol="QQQ")
                        ),
                    ),
                )
                for event in inputs.bootstrap_events
            )
            bootstrap = tuple(sorted((*inputs.bootstrap_events, *extras), key=lambda e: e.event_id))
            inputs = replace(
                inputs,
                spec=replace(
                    inputs.spec,
                    instruments=tuple(
                        sorted((*inputs.spec.instruments, ("ZZ-FIXTURE-QQQ", "QQQ")))
                    ),
                    bootstrap_events_sha256=content_digest(bootstrap),
                ),
                bootstrap_events=bootstrap,
            )
            from tests.integration.test_personal_forward_capture_journal import capture

            original_add, original_closure = Case.add_capture, Case.closure

            def capture_both(base, session):
                for instrument, symbol in base.inputs.spec.instruments:
                    base.template = replace(
                        base.template,
                        instruments=(
                            replace(
                                base.template.instruments[0],
                                instrument_id=instrument,
                                symbol=symbol,
                            ),
                        ),
                    )
                    with patch(
                        "tests.integration.test_continuous_composition.capture",
                        side_effect=lambda request, *args, **kwargs: capture(
                            replace(
                                request,
                                capture_id=request.capture_id + "-" + request.instruments[0].symbol,
                            ),
                            *args,
                            **kwargs,
                        ),
                    ):
                        publication = original_add(base, session)
                return publication

            def close_both(base, identity, at, selected=None):
                if identity == "first-close":
                    selected = tuple(
                        sorted(
                            o.observation_id
                            for o in base.source_state.observations
                            if o.payload.session == base.inputs.spec.window.scored_sessions[0]
                        )
                    )
                return original_closure(base, identity, at, selected)

            with (
                patch(
                    "tests.integration.test_continuous_composition.inputs_and_prices",
                    return_value=(inputs, prices),
                ),
                patch.object(Case, "add_capture", capture_both),
                patch.object(Case, "closure", close_both),
            ):
                self.base = Case(path)
            self.base.add_capture = lambda session: capture_both(self.base, session)
            self.base.closure = lambda identity, at, selected=None: close_both(
                self.base, identity, at, selected
            )
        else:
            self.base = Case(path)
        self.base.publish()
        previous, transition, ref, admissions = self.base.next()
        self.base.publish(transition, previous, ref, admissions)
        self.checkpoint = self.base.store.restore(self.base.scope).checkpoint
        self.sequence = 2
        self.h = self.base.h
        fixture_sources.metadata.create_all(self.base.engine)
        self.reader = FixtureObservedReader(self, self.h.store.producers)
        self.h.store.producers = self.reader
        self.accounting = PersonalAccounting()
        self.model = model(
            initial_cash_flow=self.checkpoint.state.cash_flows[0],
            instruments=self.checkpoint.inputs.spec.instruments,
            execution_policy=replace(
                self.checkpoint.inputs.spec.execution_policy, model_id="stateful-venue-facts-v1"
            ),
        )
        self.venue_engine = create_database_engine(f"sqlite+pysqlite:///{path}/venue.sqlite")
        metadata.create_all(self.venue_engine, tables=JOURNAL_TABLES)
        self.venue_objects = LocalResearchArtifactStore(path / "venue-objects")
        for payload in SOURCE_BYTES.values():
            self.venue_objects.put(payload)
        self.venue = SqlStatefulVenue(
            self.venue_engine,
            model=self.model,
            artifacts=self.venue_objects,
            codec=codec,
            verified_sources=FixtureVerifier(),
            accounting=self.accounting,
        )
        self.venue.initialize()
        self.orders = []
        mappings = []
        for commitment in self.checkpoint.state.commitments:
            submission = next(
                s for s in self.checkpoint.state.submissions if s.order_id == commitment.order_id
            )
            registration = RegisterVenueSubmission(
                account_id=self.model.account_id,
                submission=submission,
                source_commitment=commitment,
                source_risk_admission_sha256=RISK.semantic_sha256,
                source_dispatch_sha256=DISPATCH.semantic_sha256,
                venue_model_sha256=self.model.execution_policy.semantic_sha256,
            )
            outgoing = VenueSubmit(registration, reference(RISK), reference(DISPATCH))
            self.execute(outgoing, at=max(commitment.not_before, self.venue.read().state.as_of))
            self.execute(VenueAccept(commitment.order_id))
            self.orders.append(commitment.order_id)
            mappings.append(
                VenueSubmissionBinding(
                    submission,
                    registration.semantic_sha256,
                    venue_order_id(self.model, commitment.order_id),
                )
            )
        self.scope = ReconciliationScope(
            self.h.account,
            self.model.venue_id,
            "stateful_simulation",
            self.base.scope.account_binding_sha256,
            "stateful_simulation",
        )
        self.binding = VenueAccountBinding(
            self.scope,
            self.model,
            content_digest(self.model),
            tuple(sorted(mappings, key=lambda m: m.submission.order_id)),
        )
        self.applications = (
            continuous_initial_cash_application(self.checkpoint, accounting=self.accounting),
        )
        self.latest = None

    def execute(self, payload, at=None):
        state = self.venue.read().state
        command = VenueCommand(
            "observed-venue-" + str(state.sequence + 1),
            at or state.as_of + timedelta(seconds=1),
            payload,
        )
        receipt = self.venue.execute(command)
        assert receipt.acknowledgment.disposition in ("applied", "registered"), (
            receipt.acknowledgment.reasons
        )
        return receipt

    def fill(self, quantity="1", price="100", *, instrument_index=0):
        at = self.venue.read().state.as_of + timedelta(seconds=1)
        item = quote(
            at,
            name="quote-" + str(self.venue.read().state.sequence),
            budget=quantity,
            bid=price,
            ask=price,
        )
        instrument, symbol = self.model.instruments[instrument_index]
        item = replace(
            item,
            observation=replace(
                item.observation,
                payload=replace(item.observation.payload, instrument_id=instrument, symbol=symbol),
            ),
        )
        return self.execute(item, at)

    def prepare(self, name="observed", *, checked_delay=0):
        venue = self.venue.read()
        capture = SqlVenueReconciliationCapture(
            self.base.engine,
            artifacts=self.base.artifacts,
            codec=codec,
            clock=Clock(venue.state.as_of + timedelta(seconds=1)),
        ).capture(
            VenueCaptureRequest(
                name, self.binding, self.checkpoint.inputs.spec.initialized_at, venue.state.as_of
            ),
            venue=self.venue,
        )
        frontier = project_continuous_venue_frontier(
            checkpoint=self.checkpoint,
            capture=capture,
            prior_applications=self.applications,
            frontier_id=name,
            admitted_at=max(self.checkpoint.now, capture.observed.completed_at)
            + timedelta(seconds=1),
        )
        prepared = self.base.owner.prepare_frontier(
            command_id=name, checkpoint=self.checkpoint, frontier=frontier
        )
        checked_at = frontier.knowledge_at + timedelta(seconds=checked_delay)
        released = checked_at >= self.h.lease.expires_at
        if released:
            # Explicit fixture owner yields before advancing its simulated day;
            # original holds remain intact across the genuine lease generations.
            self.h.coordinator.release(self.h.lease.fence)
        self.h.clock.instant = checked_at
        if released:
            self.h.lease = self.h.coordinator.acquire("owner")
        fence = self.h.coordinator.revalidate(self.h.lease.fence)
        current = self.h.resolved()
        heads = ReconciliationHeads(
            self.checkpoint.current.snapshot.journal_sha256,
            self.checkpoint.current.snapshot.order_sha256,
            current.obligations.semantic_sha256,
            daily_runtime_effect_watermark(
                attempt_envelopes=current.attempt_envelopes, observed_groups=current.observed_groups
            ),
            daily_attempt_inventory_sha256(current.attempts),
            current.control.sequence_number,
            self.h.lease.fencing_generation,
        )
        source = RuntimeObservedHoldSource(
            scope=self.base.scope,
            coordinator_command_id=name,
            coordinator_sequence=self.sequence + 1,
            previous_checkpoint=self.put("continuous-checkpoint/1", self.checkpoint),
            resulting_checkpoint=self.put("continuous-checkpoint/1", prepared.checkpoint),
            frontier=self.put("continuous-frontier/1", frontier),
            venue_capture=self.put("venue-capture/1", capture),
            application_batches=tuple(
                self.put("applied-batch/1", batch) for batch in prepared.application_batches
            ),
            source_closure_sha256=frontier.source_frontier_sha256,
            heads=heads,
            fence=daily_fence_reference(fence),
            execution_policy=self.checkpoint.inputs.spec.execution_policy,
            applied_at=prepared.checkpoint.now,
            checked_at=fence.validated_at,
            valid_until=min(fence.valid_until, fence.validated_at + timedelta(seconds=5)),
        )
        inputs = RuntimeObservedHoldInputs(
            source, self.checkpoint, prepared.checkpoint, frontier, prepared.application_batches
        )
        source_ref = self.put("daily-observed-hold-source/1", source)
        with _write_transaction(self.base.engine) as connection:
            connection.execute(
                sa.insert(fixture_sources).values(
                    account_id=self.h.account,
                    source_id=source.semantic_sha256,
                    payload=codec.encode_record(inputs),
                )
            )
        raw = self.h.store.read_observed_hold_snapshot(
            account_id=self.h.account, fence=self.h.lease.fence, source_ref=source_ref
        )
        result = self.h.store.prepare_observed_holds(self.h.store.resolve_snapshot(raw))
        self.latest = (source, inputs, source_ref, result)
        return result

    def put(self, schema, value):
        payload = codec.encode_record(value)
        return ContinuousEvidenceRef(
            schema, self.base.artifacts.put(payload), value.semantic_sha256
        )

    def commit(self, prepared=None, *, parent=True):
        source, inputs, _, default = self.latest
        prepared = prepared or default
        parent_write = (
            prepare_parent_fixture(self.h, source)
            if parent and not prepared.retry and prepared.result.group is not None
            else None
        )
        with _write_transaction(self.base.engine) as connection:
            result = self.h.store.commit_observed_holds_in_transaction(
                connection, prepared, fence=self.h.lease.fence
            )
            if parent_write is not None:
                journal, append, values = parent_write
                journal.append_in_transaction(connection, append)
                connection.execute(sa.insert(continuous_account_commits).values(**values))
        if not prepared.retry:
            self.checkpoint = inputs.resulting
            self.sequence = source.coordinator_sequence
            found = {item.fact_id: item for item in self.applications}
            found.update(
                {
                    item.fact_id: item
                    for batch in inputs.application_batches
                    for item in batch.applications
                }
            )
            self.applications = tuple(found[key] for key in sorted(found))
        return result

    def close(self):
        self.base.engine.dispose()
        self.venue_engine.dispose()


@pytest.fixture
def case(tmp_path):
    value = ObservedCase(tmp_path)
    try:
        yield value
    finally:
        value.close()


def test_actual_partial_fill_revises_hold_without_creating_attempt(case):
    case.fill()
    prepared = case.prepare()
    original = prepared.result.before.bindings
    assert prepared.result.changed_bindings
    result = case.commit()
    restored = case.h.resolved()
    assert restored.obligations == result.after
    assert (
        tuple(b.commitment for b in restored.obligations.bindings)
        == case.checkpoint.state.commitments
    )
    assert restored.attempts == restored.attempt_envelopes == ()
    assert len(restored.observed_groups) == 1
    assert (
        daily_runtime_effect_watermark(
            attempt_envelopes=(), observed_groups=restored.observed_groups
        )
        == 3
    )
    assert all(
        replace(new, commitment=old.commitment) == old
        for old, new in zip(original, result.after.bindings, strict=True)
    )


def retry(case):
    _, _, reference, _ = case.latest
    raw = case.h.store.read_observed_hold_snapshot(
        account_id=case.h.account, fence=case.h.lease.fence, source_ref=reference
    )
    return case.h.store.prepare_observed_holds(case.h.store.resolve_snapshot(raw))


def counts(case):
    with case.base.engine.connect() as connection:
        return tuple(
            connection.scalar(sa.select(sa.func.count()).select_from(t))
            for t in (*DAILY_RUNTIME_TABLES, continuous_account_commits)
        )


@pytest.mark.parametrize("terminal", ["fill", "cancel"])
def test_partial_then_terminal_uses_canonical_holds_and_preserves_original_retry(case, terminal):
    case.fill("1")
    case.prepare("partial")
    first = case.commit()
    original = case.latest
    if terminal == "fill":
        case.fill(str(case.checkpoint.state.commitments[0].remaining_quantity))
    else:
        case.execute(VenueCancel(case.orders[0], "fixture-owner-cancel"))
    prepared = case.prepare("terminal")
    result = case.commit(prepared)
    if terminal == "fill":
        assert result.after.bindings[0].commitment.reserved_cash == 0
        assert result.after.bindings[0].commitment.remaining_quantity == 0
    else:
        # A venue cancellation without the retained coordinator CancelRequest
        # remains unresolved; it cannot manufacture terminal release authority.
        assert result.after == first.after and result.group is None
        assert result.after.bindings[0].commitment.reserved_cash > 0
        assert any(b.unresolved_fact_ids for b in case.latest[1].application_batches)
    assert case.h.resolved().attempts == ()
    before = counts(case)
    case.latest = original
    old = retry(case)
    assert old.retry and old.result == first and not old.writes
    assert case.commit(old) == first and counts(case) == before


@pytest.mark.parametrize("quantity,price", [("1", "101"), ("0", "100"), ("1", "20000")])
def test_correction_bust_and_negative_capacity_keep_actual_economic_truth(case, quantity, price):
    from packages.domain.order_reducer import BrokerOrderEventKind

    case.fill("1")
    case.prepare("opening")
    case.commit()
    before = case.checkpoint.state
    execution = next(
        e.execution_id
        for e in case.venue.read().state.accounting.broker_events
        if e.kind is BrokerOrderEventKind.EXECUTION
    )
    case.execute(
        VenueCorrect(execution, D(quantity), D(price), D(".01"), "fixture observed correction")
    )
    case.prepare("correction")
    result = case.commit()
    assert case.h.resolved().obligations == result.after
    assert case.checkpoint.state.broker_events[: len(before.broker_events)] == before.broker_events
    assert len(case.checkpoint.state.broker_events) > len(before.broker_events)
    assert not case.h.resolved().attempts
    if price == "20000":
        assert case.checkpoint.state.halted
        assert case.checkpoint.current.snapshot.trade_date_cash < 0


def test_old_applied_fact_books_with_fresh_fence_despite_expired_original_admission(case):
    case.fill()
    prepared = case.prepare("delayed-booking", checked_delay=120)
    source = case.latest[0]
    assert source.checked_at - source.applied_at == timedelta(seconds=120)
    assert source.checked_at > prepared.snapshot.admissions[0].admission.expires_at
    assert (
        source.fence.fence.fencing_generation
        > prepared.snapshot.admissions[0].admission.evidence.inputs.heads.lease_generation
    )
    assert case.commit().changed_bindings


@pytest.mark.parametrize("failure", ["missing_parent", "outer_abort", "late_commit"])
def test_atomic_observed_hold_failure_keeps_all_original_rows(case, failure):
    case.fill()
    prepared = case.prepare("rollback")
    before = counts(case)
    if failure == "missing_parent":
        with pytest.raises(sa.exc.IntegrityError):
            case.commit(parent=False)
    elif failure == "outer_abort":
        with (
            pytest.raises(RuntimeError, match="outer fixture abort"),
            _write_transaction(case.base.engine) as connection,
        ):
            case.h.store.commit_observed_holds_in_transaction(
                connection, prepared, fence=case.h.lease.fence
            )
            raise RuntimeError("outer fixture abort")
    else:

        def elapsed(connection, cursor, statement, parameters, context, many):
            if statement.startswith("INSERT INTO daily_runtime_observed_hold_groups"):
                case.h.clock.advance(timedelta(seconds=5))

        sa.event.listen(case.base.engine, "after_cursor_execute", elapsed)
        try:
            with pytest.raises(ValueError, match="expired"):
                case.commit()
        finally:
            sa.event.remove(case.base.engine, "after_cursor_execute", elapsed)
    assert counts(case) == before
    assert case.h.resolved().obligations == prepared.result.before


@pytest.mark.parametrize("field", ["result", "writes", "valid_until", "snapshot", "nested_group"])
def test_original_prepared_result_write_deadline_and_snapshot_cannot_be_replaced(case, field):
    case.fill()
    prepared = case.prepare("immutable")
    before = counts(case)
    if field == "nested_group":
        object.__setattr__(prepared.result.group.source_ref, "semantic_sha256", "f" * 64)
    else:
        value = {
            "result": replace(prepared.result, accounting_state_sha256="f" * 64),
            "writes": (),
            "valid_until": prepared.valid_until + timedelta(hours=1),
            "snapshot": replace(prepared.snapshot),
        }[field]
        object.__setattr__(prepared, field, value)
    with pytest.raises(ValueError, match="original observed"):
        case.commit(prepared)
    assert counts(case) == before


def test_observed_commit_performs_no_codec_or_accounting_under_sql(case, monkeypatch):
    case.fill()
    prepared = case.prepare("no-decoder")
    source = case.latest[0]
    journal, append, values = prepare_parent_fixture(case.h, source)

    def forbidden(*args, **kwargs):
        raise AssertionError("decode/accounting inside observed SQL")

    with monkeypatch.context() as patch:
        patch.setattr(codec, "encode_record", forbidden)
        patch.setattr(codec, "decode_record", forbidden)
        patch.setattr(case.h.store.accounting, "advance", forbidden)
        patch.setattr(case.h.store.accounting, "project", forbidden)
        with _write_transaction(case.base.engine) as connection:
            case.h.store.commit_observed_holds_in_transaction(
                connection, prepared, fence=case.h.lease.fence
            )
            journal.append_in_transaction(connection, append)
            connection.execute(sa.insert(continuous_account_commits).values(**values))
    assert case.h.resolved().obligations == prepared.result.after


def test_deleting_observed_group_cannot_hide_existing_hold_revisions(case):
    case.fill()
    case.prepare("retained")
    case.commit()
    with _write_transaction(case.base.engine) as connection:
        connection.execute(sa.delete(daily_runtime_observed_hold_groups))
    with pytest.raises(ValueError, match="hold/outbound inventory"):
        case.h.resolved()


def test_stalled_observed_replay_allows_control_writer_commit(case, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from packages.domain.operational_control import (
        OperationalControlCommandKind,
        OperationalControlState,
    )

    case.fill()
    case.prepare("stalled")
    raw = case.latest[3].snapshot.raw
    entered, release = Event(), Event()
    original = case.reader.resolve_observed_hold_sources

    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(15)
        return original(*args, **kwargs)

    monkeypatch.setattr(case.reader, "resolve_observed_hold_sources", paused)
    with ThreadPoolExecutor(max_workers=2) as pool:
        reading = pool.submit(case.h.store.resolve_snapshot, raw)
        try:
            assert entered.wait(5)
            writing = pool.submit(
                case.h.controls.apply,
                case.h.command(
                    OperationalControlCommandKind.PAUSE,
                    "observed-concurrent-pause",
                    OperationalControlState.PAUSED,
                ),
            )
            assert writing.result(timeout=5).effective_state == OperationalControlState.PAUSED
            assert not reading.done() and not release.is_set()
        finally:
            release.set()
        resolved = reading.result(timeout=10)
    prepared = case.h.store.prepare_observed_holds(resolved)
    before = counts(case)
    with pytest.raises(DailyRuntimeRiskConflict, match=r"row inventory|immutable row"):
        case.commit(prepared)
    assert counts(case) == before


@pytest.mark.parametrize("change", ["source", "original_hold", "oversized_group"])
def test_original_sources_and_bounded_group_storage_fail_closed(case, change):
    case.fill()
    prepared = case.prepare("storage")
    if change == "oversized_group":
        case.commit()
        with _write_transaction(case.base.engine) as connection:
            connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
            try:
                connection.execute(
                    sa.update(daily_runtime_observed_hold_groups).values(
                        payload=b"x" * (1048576 + 1)
                    )
                )
            finally:
                connection.exec_driver_sql("PRAGMA ignore_check_constraints=OFF")
        with pytest.raises(DailyRuntimeRiskConflict, match=r"bounded|bound|oversized|invalid"):
            case.h.resolved()
        return
    from packages.persistence.daily_runtime_risk_schema import daily_runtime_hold_events

    table = fixture_sources if change == "source" else daily_runtime_hold_events
    with _write_transaction(case.base.engine) as connection:
        connection.execute(sa.update(table).values(payload=b"tampered"))
    before = counts(case)
    with pytest.raises(DailyRuntimeRiskConflict, match="immutable row"):
        case.commit(prepared)
    assert counts(case) == before


def test_attempt_prefix_keeps_unknown_at_original_parent_sequence(activation_receipt):
    from packages.domain.daily_attempt import advance_daily_attempt
    from packages.domain.daily_attempt_contracts import DailyAttemptEnvelope
    from packages.domain.daily_observed_hold_contracts import daily_runtime_attempt_prefix
    from packages.domain.submission_attempt import SubmissionAttemptState
    from tests.unit.test_daily_attempt import (
        dispatch_case,
        event_after,
        observed_outcome,
    )

    pending, sent, _ = dispatch_case(activation_receipt)
    at = sent.events[-1].recorded_at + timedelta(microseconds=1)
    unknown = advance_daily_attempt(
        sent, event_after(sent, SubmissionAttemptState.UNKNOWN, at, reason="uncertain-delivery")
    ).attempt
    resolved = advance_daily_attempt(
        unknown,
        event_after(
            unknown,
            SubmissionAttemptState.RESOLVED,
            at + timedelta(microseconds=1),
            outcome=observed_outcome(unknown, at + timedelta(microseconds=1)),
        ),
    ).attempt
    ref = ContinuousEvidenceRef(
        "daily-attempt-accounting-source/1", resolved.events[1].dispatch.record_ref, "d" * 64
    )
    envelopes = tuple(
        DailyAttemptEnvelope(
            account_id=resolved.preparation.request.source_account_id,
            coordinator_command_id="parent-" + str(i),
            coordinator_sequence=i * 2,
            source_ref=ref,
            event=event,
        )
        for i, event in enumerate(resolved.events, 1)
    )

    def prefix(sequence, selected=envelopes):
        return daily_runtime_attempt_prefix(
            attempts=(resolved,), attempt_envelopes=selected, through_coordinator_sequence=sequence
        )

    assert prefix(0) == () and prefix(2) == (pending,)
    assert prefix(4) == (sent,) and prefix(6) == (unknown,) and prefix(8) == (resolved,)
    assert prefix(6)[0].preparation is resolved.preparation
    with pytest.raises(ValueError, match="inventory"):
        prefix(8, envelopes[1:])
    with pytest.raises(ValueError, match="immutable"):
        prefix(True)


def test_historical_observed_view_allows_later_terminal_heads_and_expired_fence(case, monkeypatch):
    case.fill("1")
    case.prepare("old-group")
    first = case.commit()
    snapshot = case.h.resolved()
    view = case.h.store.inspect_observed_group(snapshot, group=snapshot.observed_groups[0])
    case.h.store.require_observed_group_view(view)
    assert view.result == first and view.inputs.resulting == case.checkpoint
    case.fill(str(case.checkpoint.state.commitments[0].remaining_quantity))
    case.prepare("later-group", checked_delay=120)
    case.commit()

    def forbidden(*args, **kwargs):
        raise AssertionError("historical observed SQL decoded or replayed")

    with monkeypatch.context() as patch:
        patch.setattr(codec, "encode_record", forbidden)
        patch.setattr(codec, "decode_record", forbidden)
        patch.setattr(case.h.store.accounting, "advance", forbidden)
        patch.setattr(case.h.store.accounting, "project", forbidden)
        with _write_transaction(case.base.engine) as connection:
            case.h.store.recheck_observed_group_in_transaction(connection, view)
    assert view.result == first
    with _write_transaction(case.base.engine) as connection:
        connection.execute(
            sa.update(daily_runtime_observed_hold_groups)
            .where(
                daily_runtime_observed_hold_groups.c.coordinator_sequence
                == first.coordinator_sequence
            )
            .values(source_sha256="b" * 64)
        )
    with (
        pytest.raises(DailyRuntimeRiskConflict, match="immutable row"),
        _write_transaction(case.base.engine) as connection,
    ):
        case.h.store.recheck_observed_group_in_transaction(connection, view)


@pytest.mark.parametrize("mutation", ["copied", "nested"])
def test_historical_observed_view_preserves_owned_source_contents(case, mutation):
    case.fill()
    case.prepare("owned-history")
    case.commit()
    snapshot = case.h.resolved()
    view = case.h.store.inspect_observed_group(snapshot, group=snapshot.observed_groups[0])
    if mutation == "copied":
        view = replace(view)
    else:
        object.__setattr__(view.inputs.resulting.state.commitments[0], "reserved_cash", D(0))
    with pytest.raises(DailyRuntimeRiskConflict, match=r"original|owned"):
        case.h.store.require_observed_group_view(view)


@pytest.mark.parametrize("damage", [None, "changed_hold", "deleted_group", "late"])
def test_coupled_post_publication_recheck_is_exact_and_rolls_back_damage(case, damage, monkeypatch):
    from packages.persistence.daily_runtime_risk_schema import daily_runtime_hold_heads

    case.fill()
    prepared = case.prepare("coupled")
    journal, append, values = prepare_parent_fixture(case.h, case.latest[0])
    before = counts(case)

    def publish():
        with _write_transaction(case.base.engine) as connection:
            case.h.store.commit_observed_holds_in_transaction(
                connection, prepared, fence=case.h.lease.fence
            )
            journal.append_in_transaction(connection, append)
            connection.execute(sa.insert(continuous_account_commits).values(**values))
            if damage == "changed_hold":
                connection.execute(
                    sa.update(daily_runtime_hold_heads).values(semantic_sha256="c" * 64)
                )
            elif damage == "deleted_group":
                connection.execute(sa.delete(daily_runtime_observed_hold_groups))
            elif damage == "late":
                case.h.clock.advance(timedelta(seconds=5))
            return case.h.store.recheck_observed_publication_in_transaction(
                connection, prepared, fence=case.h.lease.fence
            )

    with monkeypatch.context() as patch:

        def forbidden(*args, **kwargs):
            raise AssertionError("coupled observed SQL decoded or replayed")

        patch.setattr(codec, "encode_record", forbidden)
        patch.setattr(codec, "decode_record", forbidden)
        patch.setattr(case.h.store.accounting, "advance", forbidden)
        patch.setattr(case.h.store.accounting, "project", forbidden)
        if damage is None:
            assert publish() == prepared.result
        else:
            with pytest.raises((DailyRuntimeRiskConflict, sa.exc.IntegrityError)):
                publish()
    if damage is not None:
        assert counts(case) == before
    else:
        assert case.h.resolved().obligations == prepared.result.after


def test_auxiliary_capture_bytes_remain_charged_during_observed_preparation(case, monkeypatch):
    from packages.persistence.daily_runtime_risk import MAX_TOTAL_BYTES

    original = case.reader.capture_observed_hold_sources_in_transaction

    def with_auxiliary_charge(connection, plan, *, account_id, budget):
        result = original(connection, plan, account_id=account_id, budget=budget)
        # Explicit fixture source models additional retained journal bytes. The
        # bytes are charged in capture, not fabricated as a passing source fact.
        budget.charge(0, MAX_TOTAL_BYTES - budget.payload_bytes - 1, 0)
        return result

    monkeypatch.setattr(
        case.reader, "capture_observed_hold_sources_in_transaction", with_auxiliary_charge
    )
    case.fill()
    with pytest.raises(DailyRuntimeRiskConflict, match="aggregate capture bound"):
        case.prepare("auxiliary-bound")


@pytest.mark.parametrize("damage", [None, "second_hold", "second_head"])
def test_two_actual_intents_publish_all_observed_hold_revisions_or_none(tmp_path, damage):
    from packages.persistence.daily_runtime_risk_schema import (
        daily_runtime_hold_events,
        daily_runtime_hold_heads,
    )

    case = ObservedCase(tmp_path, two=True)
    try:
        assert len(case.checkpoint.state.commitments) == 2
        case.fill("1", instrument_index=0)
        case.fill("2", instrument_index=1)
        prepared = case.prepare("two-observed-holds")
        assert len(prepared.result.changed_bindings) == 2
        assert len(prepared.result.group.changed_hold_ids) == 2
        before = counts(case)

        def fail_second(connection, cursor, statement, parameters, context, many):
            table = (
                daily_runtime_hold_events if damage == "second_hold" else daily_runtime_hold_heads
            )
            prefix = "INSERT INTO " if damage == "second_hold" else "UPDATE "
            if statement.startswith(prefix + table.name):
                fail_second.seen += 1
                if fail_second.seen == 2:
                    raise RuntimeError("second hold fixture failure")

        fail_second.seen = 0
        if damage is not None:
            sa.event.listen(case.base.engine, "after_cursor_execute", fail_second)
        try:
            if damage is None:
                result = case.commit(prepared)
                restored = case.h.resolved()
                assert restored.obligations == result.after
                assert restored.attempts == ()
                assert len(restored.observed_groups) == 1
                assert (
                    tuple(b.commitment for b in restored.obligations.bindings)
                    == case.checkpoint.state.commitments
                )
            else:
                with pytest.raises(RuntimeError, match="second hold fixture failure"):
                    case.commit(prepared)
                assert fail_second.seen == 2
                assert counts(case) == before
                assert case.h.resolved().obligations == prepared.result.before
        finally:
            if damage is not None:
                sa.event.remove(case.base.engine, "after_cursor_execute", fail_second)
    finally:
        case.close()


@pytest.mark.parametrize("changed", ["source_head", "checkpoint_mark", "source_plan"])
def test_outside_sql_prepared_guard_authenticates_nested_observed_source_graph(case, changed):
    case.fill()
    prepared = case.prepare("owned-source-graph")
    case.h.store.require_prepared_observed_holds(prepared)
    sources = prepared.snapshot.observed_sources
    inputs = sources.inputs[0]
    if changed == "source_head":
        object.__setattr__(inputs.source.heads, "attempt_sha256", "a" * 64)
    elif changed == "checkpoint_mark":
        object.__setattr__(inputs.previous.state.marks[0], "price", D("999"))
    else:
        object.__setattr__(sources.snapshot, "plan", replace(sources.snapshot.plan))
    with pytest.raises(DailyRuntimeRiskConflict, match="original observed preparation"):
        case.h.store.require_prepared_observed_holds(prepared)


@pytest.mark.parametrize("pair", [(object(), None), (None, object()), (object(), object())])
def test_post_publication_requires_complete_owned_account_source_pair(case, pair):
    case.fill()
    prepared = case.prepare("pair-reader-required")
    before = counts(case)
    journal, append, values = prepare_parent_fixture(case.h, case.latest[0])
    with (
        pytest.raises(DailyRuntimeRiskConflict, match=r"account pair|pair reader"),
        _write_transaction(case.base.engine) as connection,
    ):
        case.h.store.commit_observed_holds_in_transaction(
            connection, prepared, fence=case.h.lease.fence
        )
        journal.append_in_transaction(connection, append)
        connection.execute(sa.insert(continuous_account_commits).values(**values))
        case.h.store.recheck_observed_publication_in_transaction(
            connection,
            prepared,
            fence=case.h.lease.fence,
            prepared_account=pair[0],
            account_receipt=pair[1],
        )
    assert counts(case) == before


def retain_unknown_attempt(case):
    """Actual B pending/send/UNKNOWN history with explicitly synthetic source authority.

    Internal activation still uses the sole continuous engine. The relational
    parents and retained mark bytes are labelled fixtures; this does not qualify
    provider quote access or C dispatch publication.
    """
    from packages.application.causal_engine import continuous_runtime_action_context
    from packages.application.daily_runtime_activation import prepare_daily_runtime_activation
    from packages.domain.accounting_contracts import AccountingCommand
    from packages.domain.continuous_engine_contracts import ClosedEngineFrontier
    from packages.domain.continuous_runtime_action import ContinuousRuntimeAction
    from packages.domain.daily_attempt import (
        prepare_daily_activation,
        prepare_daily_attempt,
        prepare_daily_dispatch,
    )
    from packages.domain.daily_attempt_contracts import (
        DailyAttemptEvent,
        DailyDispatchClaim,
        DailyDispatchRecord,
        DailyVenueSubmissionRequest,
    )
    from packages.domain.daily_risk import evaluate_daily_risk
    from packages.domain.durable_journal_contracts import (
        JournalAppend,
        JournalKey,
        JournalRecord,
        empty_head,
    )
    from packages.domain.engine_contracts import EngineEvent
    from packages.domain.submission_attempt import SubmissionAttemptState
    from packages.persistence.daily_runtime_risk import RuntimeAttemptAccountingSource
    from packages.persistence.durable_journal import SqlDurableJournal
    from tests.integration.test_sql_daily_runtime_risk import (
        AttemptFixtureReader,
        commit_attempt,
        envelope_for,
        prepare_attempt,
        retain_attempt_source,
    )
    from tests.unit.test_daily_attempt import event_after, rebind_case, reference
    from tests.unit.test_daily_risk_snapshot import build, runtime_case

    h = case.h
    case.reader.delegate = AttemptFixtureReader(h.account)
    current = h.resolved()
    record = current.admissions[0]
    retained = case.put("daily-admission-producer/1", record)
    preparations = tuple(
        prepare_daily_attempt(
            request=DailyVenueSubmissionRequest(
                submission=next(
                    s
                    for s in case.checkpoint.state.submissions
                    if s.order_id == binding.commitment.order_id
                ),
                original_commitment=binding.commitment,
                source_account_id=h.account,
                source_account_binding_sha256=h.assignment.account_binding_sha256,
                venue_account_id=case.model.account_id,
                venue_model=reference(case.model),
                original_admission_sha256=record.admission.semantic_sha256,
            ),
            original_admission=record.admission,
            admission_source=reference(record),
            original_hold=binding,
            prepared_at=case.checkpoint.now,
        )
        for binding in current.obligations.bindings
    )

    def source(name, *, context=None, command=None):
        snapshot = case.checkpoint.current.snapshot
        current = h.resolved()
        return RuntimeAttemptAccountingSource(
            account_id=h.account,
            coordinator_command_id=name,
            coordinator_sequence=case.sequence + 1,
            state=case.checkpoint.state,
            context=context
            or continuous_runtime_action_context(
                case.checkpoint, command_id=name, activation=False
            ),
            execution_policy=case.checkpoint.inputs.spec.execution_policy,
            obligations=current.obligations,
            heads=ReconciliationHeads(
                snapshot.journal_sha256,
                snapshot.order_sha256,
                current.obligations.semantic_sha256,
                daily_runtime_effect_watermark(
                    attempt_envelopes=current.attempt_envelopes,
                    observed_groups=current.observed_groups,
                ),
                daily_attempt_inventory_sha256(current.attempts),
                current.control.sequence_number,
                h.lease.fencing_generation,
            ),
            fence=daily_fence_reference(h.coordinator.revalidate(h.lease.fence)),
            checked_at=h.clock.instant,
            valid_until=h.clock.instant + timedelta(seconds=1),
            accounting_command=command,
            source_references=(retained,),
        )

    pending_source = source("actual-pending")
    ref = retain_attempt_source(h, pending_source)
    envelopes = tuple(
        envelope_for(
            pending_source,
            ref,
            DailyAttemptEvent(
                attempt_id=p.attempt_id,
                sequence=1,
                previous_event_sha256=None,
                state=SubmissionAttemptState.PENDING,
                recorded_at=h.clock.instant,
            ),
        )
        for p in preparations
    )
    pending = commit_attempt(h, pending_source, prepare_attempt(h, envelopes, preparations))
    case.sequence = pending_source.coordinator_sequence
    at = case.checkpoint.state.commitments[0].not_before
    h.coordinator.release(h.lease.fence)
    h.clock.instant = at
    h.lease = h.coordinator.acquire("owner")
    assert case.checkpoint.inputs.spec.source_mode == "synthetic_observed"
    events = []
    for old in case.checkpoint.state.marks:
        hold = next(
            c for c in case.checkpoint.state.commitments if c.instrument_id == old.instrument_id
        )
        mark = replace(
            old,
            mark_id="send-mark-" + old.mark_id,
            economic_at=at,
            knowledge_at=at,
            session=hold.execution_session,
            basis="runtime_quote_ask_v1",
        )
        command = AccountingCommand(mark.mark_id, mark)
        raw_mark = case.base.artifacts.put(codec.encode_record(command))
        provenance = replace(
            case.checkpoint.inputs.bootstrap_events[0].provenance,
            normalized_sha256=content_digest(command),
            source_namespace="explicit-retained-mark-fixture-not-provider",
            observed_at=None,
            simulated_available_at=at,
            assumption_id="explicit-retained-mark-fixture/1",
            raw_sha256=raw_mark.object_sha256,
            limitations=("fixture mark bytes and fixture clock; no provider quote qualification",),
        )
        events.append(EngineEvent(mark.mark_id, at, at, command, provenance))
    frontier = ClosedEngineFrontier(
        frontier_id="explicit-fixture-send-mark",
        stream_id=case.checkpoint.inputs.spec.run_id,
        previous_checkpoint_sha256=case.checkpoint.semantic_sha256,
        source_frontier_sha256="a" * 64,
        knowledge_at=at,
        events=tuple(sorted(events, key=lambda e: e.event_id)),
    )
    case.checkpoint = case.base.owner.prepare_frontier(
        command_id=frontier.frontier_id, checkpoint=case.checkpoint, frontier=frontier
    ).checkpoint
    activation_source = source("actual-send")
    snapshot = case.checkpoint.current.snapshot
    batch = replace(record.admission.decision.batch, snapshot_sha256=snapshot.semantic_sha256)
    inputs = runtime_case(
        snapshot=snapshot,
        batch=batch,
        phase="activation",
        now=at,
        bindings=pending.obligations.bindings,
    )[3]
    inputs = replace(
        inputs,
        heads=activation_source.heads,
        source_session=batch.target.trigger.source_session,
        execution_session=batch.target.trigger.execution_session,
        sources=tuple(
            replace(item, account_binding_sha256=h.assignment.account_binding_sha256)
            for item in inputs.sources
        ),
        reconciliation=replace(
            inputs.reconciliation,
            scope=replace(
                inputs.reconciliation.scope, binding_sha256=h.assignment.account_binding_sha256
            ),
            heads=activation_source.heads,
        ),
        accepted_intent_ids=tuple(
            sorted(b.commitment.intent_id for b in pending.obligations.bindings)
        ),
    )
    risk_case = rebind_case(
        (h.assignment, snapshot, batch, inputs, h.producer_map, at), account_id=h.account
    )
    evidence = build(risk_case)
    decision = evaluate_daily_risk(h.assignment.policy, snapshot, batch, evidence, at)
    assert decision.approved, decision.reasons
    dispatches = tuple(
        prepare_daily_dispatch(
            attempt=attempt,
            activation=prepare_daily_activation(
                preparation=attempt.preparation,
                current_hold=next(
                    b
                    for b in pending.obligations.bindings
                    if b.commitment.commitment_id
                    == attempt.preparation.original_hold.commitment.commitment_id
                ),
                snapshot=snapshot,
                evidence=evidence,
                decision=decision,
                heads=activation_source.heads,
                fence=activation_source.fence,
                checked_at=at,
            ),
            command_id="actual-send-" + attempt.attempt_id,
            dispatched_at=at,
        )
        for attempt in pending.attempts
    )
    context = continuous_runtime_action_context(
        case.checkpoint, command_id="actual-send-accounting", activation=True
    )
    activation = prepare_daily_runtime_activation(
        state=case.checkpoint.state,
        context=context,
        execution_policy=activation_source.execution_policy,
        attempts=pending.attempts,
        dispatches=dispatches,
        accounting=case.accounting,
    )
    activation_source = replace(
        activation_source, context=context, accounting_command=activation.command
    )
    action = ContinuousRuntimeAction(
        action_id="actual-send-action",
        stream_id=case.checkpoint.inputs.spec.run_id,
        previous_checkpoint_sha256=case.checkpoint.semantic_sha256,
        source_closure_sha256=activation_source.semantic_sha256,
        checked_at=at,
        command=activation.command,
    )
    activated_checkpoint = case.base.owner.prepare_runtime_action(
        command_id="actual-send", checkpoint=case.checkpoint, action=action
    ).checkpoint
    ref = retain_attempt_source(h, activation_source)
    journal = SqlDurableJournal(
        h.engine, codec=codec, record_types={"daily-dispatch/1": DailyDispatchRecord}
    )
    request = preparations[0].request
    key = JournalKey(
        "coordinator",
        "dispatch-" + h.account,
        h.account,
        "daily-dispatch/1",
        "synthetic",
        content_digest(
            (
                "daily-dispatch-scope/1",
                request.source_account_id,
                request.source_account_binding_sha256,
                request.venue_account_id,
                request.venue_model,
            )
        ),
    )
    head, appends, envelopes = empty_head(key), [], []
    for attempt, dispatch in zip(pending.attempts, dispatches, strict=True):
        payload = codec.encode_record(dispatch)
        append = journal.prepare_append(
            key,
            JournalAppend(
                dispatch.command_id,
                dispatch.semantic_sha256,
                head,
                (JournalRecord(dispatch.record_id, "daily-dispatch/1", payload),),
            ),
        )
        head = append.receipt.committed_head
        claim = DailyDispatchClaim(
            record=dispatch, receipt=append.receipt, record_ref=case.base.artifacts.put(payload)
        )
        envelopes.append(
            envelope_for(
                activation_source,
                ref,
                DailyAttemptEvent(
                    attempt_id=attempt.attempt_id,
                    sequence=2,
                    previous_event_sha256=attempt.events[-1].semantic_sha256,
                    state=SubmissionAttemptState.IN_FLIGHT,
                    recorded_at=at,
                    dispatch=claim,
                ),
            )
        )
        appends.append(append)
    sent = commit_attempt(
        h,
        activation_source,
        prepare_attempt(
            h, tuple(envelopes), dispatch_journal=journal, dispatch_appends=tuple(appends)
        ),
    )
    assert sent.accounting_state == activated_checkpoint.state
    case.checkpoint = activated_checkpoint
    case.sequence = activation_source.coordinator_sequence
    unknown_source = source("actual-unknown")
    ref = retain_attempt_source(h, unknown_source)
    unknown_event = event_after(
        sent.attempts[0],
        SubmissionAttemptState.UNKNOWN,
        at,
        reason="explicit-fixture-uncertain-delivery",
    )
    unknown = commit_attempt(
        h, unknown_source, prepare_attempt(h, (envelope_for(unknown_source, ref, unknown_event),))
    )
    case.sequence = unknown_source.coordinator_sequence
    return unknown


def test_actual_unknown_survives_partial_and_terminal_observed_economics(case):
    unknown = retain_unknown_attempt(case)
    assert unknown.attempts[0].state.value == "unknown"
    case.fill("1")
    prepared = case.prepare("partial-after-unknown")
    first = case.commit(prepared)
    restored = case.h.resolved()
    assert restored.attempts == unknown.attempts
    assert restored.obligations == first.after
    assert restored.obligations != unknown.obligations
    original_group = restored.observed_groups[0]
    old_view = case.h.store.inspect_observed_group(restored, group=original_group)
    case.fill(str(case.checkpoint.state.commitments[0].remaining_quantity))
    terminal = case.commit(case.prepare("terminal-after-unknown"))
    restored = case.h.resolved()
    assert restored.attempts == unknown.attempts
    assert restored.obligations == terminal.after
    assert terminal.after.bindings[0].commitment.reserved_cash == 0
    assert terminal.after.bindings[0].commitment.state == "terminal"
    assert (
        restored.attempts[0].preparation.original_hold
        == unknown.attempts[0].preparation.original_hold
    )
    case.h.store.require_observed_group_view(old_view)
    with _write_transaction(case.base.engine) as connection:
        case.h.store.recheck_observed_group_in_transaction(connection, old_view)
    assert case.h.store.inspect_observed_group(restored, group=original_group).result == first
