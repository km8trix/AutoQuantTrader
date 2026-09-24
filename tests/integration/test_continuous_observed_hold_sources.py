"""Actual independent venue/engine/C metadata evidence; no fixture parent rows."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.application.continuous_venue_frontier import (
    continuous_initial_cash_application,
    project_continuous_venue_frontier,
)
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.stateful_venue_contracts import VenueCommand
from packages.domain.venue_reconciliation_contracts import VenueCaptureRequest
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_observed_hold_sources import (
    ContinuousObservedHoldSourceError,
    SqlContinuousObservedHoldSources,
)
from packages.persistence.daily_runtime_risk import RuntimeReadBudget, capture_runtime_table
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
from tests.integration.test_continuous_reconciliation_publication import PublicationCase
from tests.integration.test_sql_daily_runtime_risk import _write_transaction
from tests.integration.test_venue_reconciliation_capture import Clock


def resolver(case):
    return SqlContinuousObservedHoldSources(
        case.base.engine,
        accounts=case.account,
        preparer=case.base.owner,
        venue_sources=case.sources,
        daily=case.base.h.store,
        artifacts=case.base.artifacts,
        codec=codec,
    )


def retain(case, reader, *, name="observed", applications=None):
    b = case.base
    previous = case.account.restore(b.scope)
    assert previous is not None
    independent = case.venue.read()
    captured = SqlVenueReconciliationCapture(
        b.engine,
        artifacts=b.artifacts,
        codec=codec,
        clock=Clock(max(independent.state.as_of, previous.checkpoint.now) + timedelta(seconds=1)),
    ).capture(
        VenueCaptureRequest(
            name, case.binding, b.inputs.spec.initialized_at, independent.state.as_of
        ),
        venue=case.venue,
    )
    original = applications or (
        continuous_initial_cash_application(previous.checkpoint, accounting=case.accounting),
    )
    frontier = project_continuous_venue_frontier(
        checkpoint=previous.checkpoint,
        capture=captured,
        prior_applications=original,
        frontier_id=name,
        admitted_at=max(previous.checkpoint.now, captured.observed.completed_at)
        + timedelta(seconds=1),
    )
    transition = b.owner.prepare_frontier(
        command_id=name, checkpoint=previous.checkpoint, frontier=frontier
    )
    b.h.clock.instant = frontier.knowledge_at
    current = b.h.resolved()
    return reader.retain_source(
        previous=previous,
        transition=transition,
        venue=case.sources.resolve(captured),
        current=current,
    )


def publish(case, token):
    prepared = case.account.prepare(
        token.transition,
        scope=case.base.scope,
        previous=token.previous,
        source_evidence=token.inputs.source.venue_capture,
    )
    with case.account.write_transaction() as connection:
        return case.account.commit_in_transaction(
            connection, prepared=prepared, fence=case.base.h.lease.fence
        )


def capture(case, reader, plan, *, reused=False):
    budget = RuntimeReadBudget()
    with _write_transaction(case.base.engine) as connection:
        original = None
        if reused:
            original = capture_runtime_table(
                connection,
                continuous_account_commits,
                account_id=case.base.h.account,
                budget=budget,
            )
        raw = reader.capture_observed_hold_sources_in_transaction(
            connection, plan, account_id=case.base.h.account, budget=budget
        )
    if reused:
        assert raw.tables == ()
        assert raw.state.account_rows is original
    else:
        assert len(raw.tables) == 1
    assert budget.rows > len(raw.state.account_rows.rows)
    return raw


@pytest.fixture
def case(tmp_path):
    value = PublicationCase(tmp_path)
    try:
        yield value
    finally:
        value.close()


def test_actual_fresh_then_published_source_resolves_without_recursive_restore(case, monkeypatch):
    reader = resolver(case)
    token = retain(case, reader)
    plan = reader.prepare_observed_hold_source_read((token.reference,))
    fresh = reader.resolve_observed_hold_sources(capture(case, reader, plan), admissions=())
    assert fresh.inputs == (token.inputs,)
    reader.require_resolved(fresh)
    receipt = publish(case, token)
    assert receipt.commit.sequence == 2
    restarted = resolver(case)

    def forbidden(*args, **kwargs):
        raise AssertionError("recursive restore/composer forbidden")

    monkeypatch.setattr(case.account, "restore", forbidden)
    monkeypatch.setattr(case.account.composer, "prepare_capture", forbidden)
    plan = restarted.prepare_observed_hold_source_read((token.reference,))
    restored = restarted.resolve_observed_hold_sources(
        capture(case, restarted, plan, reused=True), admissions=()
    )
    assert restored.inputs == (token.inputs,)
    restarted.require_resolved(restored)
    with _write_transaction(case.base.engine) as connection:
        restarted.recheck_observed_hold_sources_in_transaction(connection, restored)


def test_restart_without_actual_parent_cannot_promote_retained_source(case):
    reader = resolver(case)
    token = retain(case, reader)
    restarted = resolver(case)
    plan = restarted.prepare_observed_hold_source_read((token.reference,))
    with pytest.raises(ContinuousObservedHoldSourceError, match="ACTUAL_PARENT_OR_FRESH"):
        capture(case, restarted, plan)


def test_actual_external_cash_binds_engine_links_original_times_and_parent(case):
    at = case.base.first.checkpoint.now + timedelta(seconds=1)
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(500),
        effective_at=at,
        recorded_at=at,
        external_reference="source-cash",
    )
    case.venue.execute(VenueCommand("source-cash", at, flow))
    reader = resolver(case)
    token = retain(case, reader)
    assert token.inputs.resulting.current.snapshot.trade_date_cash == Decimal(10500)
    assert token.inputs.resulting.state.halted
    assert token.inputs.resulting.flows[-1].flow.cash_flow_id == flow.cash_flow_id
    applied = tuple(a for batch in token.inputs.application_batches for a in batch.applications)
    original = next(a for a in applied if a.fact_id == flow.cash_flow_id)
    assert original.journal_entry_ids
    publish(case, token)
    restarted = resolver(case)
    plan = restarted.prepare_observed_hold_source_read((token.reference,))
    restored = restarted.resolve_observed_hold_sources(
        capture(case, restarted, plan), admissions=()
    )
    assert restored.inputs[0].application_batches == token.inputs.application_batches
    assert (
        next(
            a
            for b in restored.inputs[0].application_batches
            for a in b.applications
            if a.fact_id == flow.cash_flow_id
        ).applied_at
        == original.applied_at
    )


def test_aggregate_object_admission_precedes_any_object_read(case, monkeypatch):
    from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
    from packages.domain.research_job_contracts import ObjectRef

    reader = resolver(case)
    refs = tuple(
        ContinuousEvidenceRef(
            "daily-observed-hold-source/1", ObjectRef(digit * 64, 17 * 1024 * 1024), digit * 64
        )
        for digit in ("a", "b")
    )

    def forbidden(*args, **kwargs):
        pytest.fail("objects must not be read after aggregate admission fails")

    monkeypatch.setattr(case.base.artifacts, "read", forbidden)
    with pytest.raises(ContinuousObservedHoldSourceError, match="COMPLETE_OBJECT_GRAPH_LIMIT"):
        reader.prepare_observed_hold_source_read(refs)


def test_actual_source_capture_and_final_recheck_do_no_heavy_work_under_sql(case, monkeypatch):
    reader = resolver(case)
    token = retain(case, reader)
    publish(case, token)
    reader = resolver(case)
    plan = reader.prepare_observed_hold_source_read((token.reference,))
    active = set()
    hooks = (
        ("begin", lambda conn: active.add(id(conn))),
        ("commit", lambda conn: active.discard(id(conn))),
        ("rollback", lambda conn: active.discard(id(conn))),
    )
    for name, hook in hooks:
        sa.event.listen(case.base.engine, name, hook)

    def guard(original):
        def call(*args, **kwargs):
            assert not active, "heavy work under source SQL transaction"
            return original(*args, **kwargs)

        return call

    for obj, name in (
        (codec, "encode_record"),
        (codec, "decode_record"),
        (case.base.artifacts, "read"),
        (case.base.owner, "prepare_frontier"),
        (case.sources, "require_resolved"),
        (case.account, "require_reference"),
        (case.account, "resolve_reference"),
    ):
        monkeypatch.setattr(obj, name, guard(getattr(obj, name)))
    try:
        raw = capture(case, reader, plan)
        restored = reader.resolve_observed_hold_sources(raw, admissions=())
        reader.require_resolved(restored)
        with _write_transaction(case.base.engine) as connection:
            reader.recheck_observed_hold_sources_in_transaction(connection, restored)
    finally:
        for name, hook in hooks:
            sa.event.remove(case.base.engine, name, hook)


@pytest.mark.parametrize("changed", ["checkpoint", "source", "wrapper", "plan"])
def test_owned_original_graph_rejects_mutation(case, changed):
    reader = resolver(case)
    token = retain(case, reader)
    if changed == "wrapper":
        with pytest.raises(ContinuousObservedHoldSourceError, match="OWNED_ORIGINAL"):
            reader.require_prepared(replace(token))
        return
    if changed == "plan":
        plan = reader.prepare_observed_hold_source_read((token.reference,))
        object.__setattr__(
            plan.state, "inputs", tuple(reversed((*plan.state.inputs, *plan.state.inputs)))
        )
        with pytest.raises(ContinuousObservedHoldSourceError, match="OWNED_ORIGINAL"):
            capture(case, reader, plan)
        return
    plan = reader.prepare_observed_hold_source_read((token.reference,))
    restored = reader.resolve_observed_hold_sources(capture(case, reader, plan), admissions=())
    if changed == "checkpoint":
        object.__setattr__(
            restored.inputs[0].resulting,
            "now",
            restored.inputs[0].resulting.now + timedelta(microseconds=1),
        )
    else:
        object.__setattr__(restored.inputs[0].source, "coordinator_sequence", 17)
    with pytest.raises(ContinuousObservedHoldSourceError, match="CONTENT_CHANGED"):
        reader.require_resolved(restored)


def test_actual_parent_index_tamper_rejects_final_recheck(case):
    reader = resolver(case)
    token = retain(case, reader)
    publish(case, token)
    reader = resolver(case)
    plan = reader.prepare_observed_hold_source_read((token.reference,))
    restored = reader.resolve_observed_hold_sources(capture(case, reader, plan), admissions=())
    with _write_transaction(case.base.engine) as connection:
        connection.execute(
            sa.update(continuous_account_commits)
            .where(
                continuous_account_commits.c.command_id
                == token.inputs.source.coordinator_command_id
            )
            .values(checkpoint_sha256="d" * 64)
        )
    with (
        _write_transaction(case.base.engine) as connection,
        pytest.raises(ContinuousObservedHoldSourceError, match="RECHECK_FAILED"),
    ):
        reader.recheck_observed_hold_sources_in_transaction(connection, restored)


def test_historical_parent_sequence_must_match_retained_source(case):
    reader = resolver(case)
    token = retain(case, reader)
    publish(case, token)
    forged = replace(token.inputs.source, coordinator_sequence=3)
    forged_ref = case.base.put("daily-observed-hold-source/1", forged)
    restarted = resolver(case)
    plan = restarted.prepare_observed_hold_source_read((forged_ref,))
    with pytest.raises(
        ContinuousObservedHoldSourceError, match="ACTUAL_PARENT_PUBLICATION_DIFFERS"
    ):
        restarted.resolve_observed_hold_sources(capture(case, restarted, plan), admissions=())


def test_fresh_source_cannot_survive_account_advance_before_publication(case):
    reader = resolver(case)
    token = retain(case, reader, name="unpublished-source")
    other = retain(case, reader, name="other-source")
    publish(case, other)
    plan = reader.prepare_observed_hold_source_read((token.reference,))
    with pytest.raises(ContinuousObservedHoldSourceError, match="FRESH_CURRENT_ACCOUNT_DIFFERS"):
        capture(case, reader, plan)


def test_actual_partial_fill_source_drives_b_preparation_without_fixture_parent(tmp_path):
    from packages.application.continuous_reconciliation import (
        ContinuousReconciliationTransitionResolver,
    )
    from packages.application.venue_reconciliation import VenueReconciliationResolver
    from packages.persistence.continuous_venue_sources import SqlContinuousVenueSources
    from tests.integration.test_daily_observed_holds import ObservedCase

    c = ObservedCase(tmp_path)
    try:
        b, h = c.base, c.h
        previous = b.store.restore(b.scope)
        c.fill("1")
        independent = c.venue.read()
        captured = SqlVenueReconciliationCapture(
            b.engine,
            artifacts=b.artifacts,
            codec=codec,
            clock=Clock(independent.state.as_of + timedelta(seconds=1)),
        ).capture(
            VenueCaptureRequest(
                "actual-partial", c.binding, b.inputs.spec.initialized_at, independent.state.as_of
            ),
            venue=c.venue,
        )
        frontier = project_continuous_venue_frontier(
            checkpoint=previous.checkpoint,
            capture=captured,
            prior_applications=c.applications,
            frontier_id="actual-partial",
            admitted_at=captured.observed.completed_at + timedelta(seconds=1),
        )
        transition = b.owner.prepare_frontier(
            command_id="actual-partial", checkpoint=previous.checkpoint, frontier=frontier
        )
        expired = frontier.knowledge_at >= h.lease.expires_at
        if expired:
            h.coordinator.release(h.lease.fence)
        h.clock.instant = frontier.knowledge_at
        if expired:
            h.lease = h.coordinator.acquire("owner")
        current = h.resolved()
        venue_sources = SqlContinuousVenueSources(
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
        reader = SqlContinuousObservedHoldSources(
            b.engine,
            accounts=b.store,
            preparer=b.owner,
            venue_sources=venue_sources,
            daily=h.store,
            artifacts=b.artifacts,
            codec=codec,
        )
        token = reader.retain_source(
            previous=previous,
            transition=transition,
            venue=venue_sources.resolve(captured),
            current=current,
        )
        old = h.store.producers

        class DelegatingReader:
            def __getattr__(self, name):
                if "observed_hold_source" in name or "observed_hold_sources" in name:
                    return getattr(reader, name)
                return getattr(old, name)

        h.store.producers = DelegatingReader()
        raw = h.store.read_observed_hold_snapshot(
            account_id=h.account, fence=h.lease.fence, source_ref=token.reference
        )
        resolved = h.store.resolve_snapshot(raw)
        prepared = h.store.prepare_observed_holds(resolved)
        assert len(prepared.result.changed_bindings) == 1
        before = prepared.result.before.bindings[0].commitment
        after = prepared.result.after.bindings[0].commitment
        assert after.remaining_quantity == before.remaining_quantity - Decimal(1)
        assert after.reserved_cash < before.reserved_cash
        assert after.commitment_id == before.commitment_id
        assert resolved.attempts == ()
        assert prepared.result.group.coordinator_sequence == previous.receipt.commit.sequence + 1
        # B/C publication is root's coupled transaction; no fabricated parent here.
        with b.engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(continuous_account_commits)
                )
                == 2
            )
    finally:
        c.close()


def test_original_source_lease_and_parent_later_heartbeat_are_distinct(case):
    reader = resolver(case)
    token = retain(case, reader)
    original_lease = token.inputs.source.fence.lease_sha256
    case.base.h.clock.instant += timedelta(seconds=1)
    case.base.h.lease = case.base.h.coordinator.renew(case.base.h.lease.fence)
    receipt = publish(case, token)
    assert receipt.fence_reference.lease_sha256 != original_lease
    reader = resolver(case)
    plan = reader.prepare_observed_hold_source_read((token.reference,))
    restored = reader.resolve_observed_hold_sources(capture(case, reader, plan), admissions=())
    assert restored.state.references[0].source_lease.semantic_sha256 == original_lease
    assert (
        restored.state.references[0].receipt.fence_reference.lease_sha256
        == receipt.fence_reference.lease_sha256
    )
    with _write_transaction(case.base.engine) as connection:
        reader.recheck_observed_hold_sources_in_transaction(connection, restored)


def test_original_historical_rows_remain_valid_after_later_capture_head_and_expiry(case):
    reader = resolver(case)
    token = retain(case, reader)
    publish(case, token)
    original_reader = resolver(case)
    plan = original_reader.prepare_observed_hold_source_read((token.reference,))
    original = original_reader.resolve_observed_hold_sources(
        capture(case, original_reader, plan), admissions=()
    )
    applications = tuple(a for b in token.inputs.application_batches for a in b.applications)
    later = retain(case, reader, name="later", applications=applications)
    publish(case, later)
    case.base.h.clock.instant = later.inputs.source.valid_until + timedelta(days=1)
    restarted = resolver(case)
    plan = restarted.prepare_observed_hold_source_read((token.reference,))
    restored = restarted.resolve_observed_hold_sources(
        capture(case, restarted, plan), admissions=()
    )
    assert restored.inputs == original.inputs
    assert restored.inputs[0].source.checked_at == token.inputs.source.checked_at
    restarted.require_resolved(restored)
    with _write_transaction(case.base.engine) as connection:
        restarted.recheck_observed_hold_sources_in_transaction(connection, restored)


def test_stale_fresh_source_rejects_actual_fence_expiry(case):
    reader = resolver(case)
    token = retain(case, reader)
    plan = reader.prepare_observed_hold_source_read((token.reference,))
    restored = reader.resolve_observed_hold_sources(capture(case, reader, plan), admissions=())
    case.base.h.clock.instant = token.inputs.source.valid_until
    with (
        _write_transaction(case.base.engine) as connection,
        pytest.raises(ContinuousObservedHoldSourceError, match="RECHECK_FAILED"),
    ):
        reader.recheck_observed_hold_sources_in_transaction(connection, restored)


def test_oversized_original_journal_rejects_before_payload_decoder(case, monkeypatch):
    from packages.domain.durable_journal_contracts import MAX_RECORD_BYTES, JournalKey
    from packages.persistence.durable_journal import JournalConflict
    from packages.persistence.durable_journal_schema import journal_entries

    reader = resolver(case)
    token = retain(case, reader)
    publish(case, token)
    reader = resolver(case)
    plan = reader.prepare_observed_hold_source_read((token.reference,))
    source = token.venue.capture.manifest.sources[0]
    with _write_transaction(case.base.engine) as connection:
        updated = connection.execute(
            sa.update(journal_entries)
            .where(
                journal_entries.c.key_sha256 == source.key.semantic_sha256,
                journal_entries.c.command_id == source.receipt.command_id,
            )
            .values(payload=sa.func.zeroblob(2 * 1024 * 1024))
        )
        assert updated.rowcount == 1
        assert (
            connection.execute(
                sa.select(sa.func.length(journal_entries.c.payload)).where(
                    journal_entries.c.key_sha256 == source.key.semantic_sha256,
                    journal_entries.c.command_id == source.receipt.command_id,
                )
            ).scalar_one()
            == 2 * 1024 * 1024
        )

    decoded = []
    decode = codec.decode_record

    def only_key(raw, kind):
        assert kind is JournalKey, "oversized entry must reject before payload decoding"
        assert len(raw) <= 16 * 1024
        decoded.append(kind)
        return decode(raw, kind)

    # Capture bounds transfer with a limit + 1 invalid-field sentinel. It does
    # not perform journal validation or typed decoding inside the SQL snapshot.
    raw = capture(case, reader, plan)
    journal = raw.state.venue_journals[0][0]
    assert journal.requested_receipt is not None
    assert len(journal.requested_receipt.entries[0]["payload"]) == MAX_RECORD_BYTES + 1
    with monkeypatch.context() as guarded:
        guarded.setattr(codec, "decode_record", only_key)
        with pytest.raises(JournalConflict, match="JOURNAL_ENTRY_INVALID"):
            reader.venue_sources.journal.resolve_snapshot(journal)
    assert decoded == [JournalKey]
    with pytest.raises(ContinuousObservedHoldSourceError, match="RESOLUTION_FAILED"):
        reader.resolve_observed_hold_sources(raw, admissions=())


def test_shared_sql_budget_is_charged_for_auxiliary_original_rows(case):
    from packages.persistence.daily_runtime_risk import MAX_METADATA_BYTES

    reader = resolver(case)
    token = retain(case, reader)
    plan = reader.prepare_observed_hold_source_read((token.reference,))
    with _write_transaction(case.base.engine) as connection:
        budget = RuntimeReadBudget()
        capture_runtime_table(
            connection, continuous_account_commits, account_id=case.base.h.account, budget=budget
        )
        budget.charge(0, 0, MAX_METADATA_BYTES - budget.metadata_bytes)
        with pytest.raises(ContinuousObservedHoldSourceError, match="CAPTURE_FAILED"):
            reader.capture_observed_hold_sources_in_transaction(
                connection, plan, account_id=case.base.h.account, budget=budget
            )


def test_retained_wall_observation_is_bounded_and_only_replay_exception(case):
    from packages.persistence.continuous_observed_hold_sources import _same_replayed_checkpoint

    reader = resolver(case)
    token = retain(case, reader)
    checkpoint = token.inputs.resulting
    # A subsequent step's independently measured allowance may exceed its
    # predecessor's residue; the retained value is never overwritten by replay.
    observed = replace(
        checkpoint, remaining_wall_nanoseconds=checkpoint.inputs.spec.max_wall_seconds * 10**9
    )
    measured = replace(checkpoint, remaining_wall_nanoseconds=1)
    assert _same_replayed_checkpoint(observed, measured)
    assert not _same_replayed_checkpoint(replace(observed, remaining_wall_nanoseconds=0), measured)
    assert not _same_replayed_checkpoint(
        observed, replace(measured, now=measured.now + timedelta(microseconds=1))
    )


def _prepare_publication(case, reader):
    token = retain(case, reader)
    plan = reader.prepare_observed_hold_source_read((token.reference,))
    resolved = reader.resolve_observed_hold_sources(capture(case, reader, plan), admissions=())
    reader.require_resolved(resolved)
    prepared = case.account.prepare(
        token.transition,
        scope=case.base.scope,
        previous=token.previous,
        source_evidence=token.inputs.source.venue_capture,
    )
    return token, resolved, prepared


def test_actual_post_publication_recheck_requires_owned_pair_and_no_heavy_work(case, monkeypatch):
    reader = resolver(case)
    _, resolved, prepared = _prepare_publication(case, reader)
    with monkeypatch.context() as guarded, case.account.write_transaction() as connection:
        receipt = case.account.commit_in_transaction(
            connection, prepared=prepared, fence=case.base.h.lease.fence
        )

        def forbidden(*args, **kwargs):
            pytest.fail("post-publication source readback must not decode, hash or replay objects")

        for obj, name in (
            (codec, "encode_record"),
            (codec, "decode_record"),
            (case.base.artifacts, "read"),
            (case.base.owner, "prepare_frontier"),
            (case.sources, "require_resolved"),
            (case.account, "resolve_reference"),
            (reader, "_fingerprint"),
            (reader, "require_resolved"),
        ):
            guarded.setattr(obj, name, forbidden)
        with pytest.raises(ContinuousObservedHoldSourceError, match="CURRENT_ACCOUNT_CHANGED"):
            reader.recheck_observed_hold_sources_in_transaction(connection, resolved)
        reader.recheck_observed_hold_sources_after_publication_in_transaction(
            connection, resolved, prepared_account=prepared, account_receipt=receipt
        )
        for supplied_prepared, supplied_receipt in (
            (replace(prepared), receipt),
            (prepared, replace(receipt)),
            (object(), receipt),
            (prepared, object()),
        ):
            with pytest.raises(ContinuousObservedHoldSourceError):
                reader.recheck_observed_hold_sources_after_publication_in_transaction(
                    connection,
                    resolved,
                    prepared_account=supplied_prepared,
                    account_receipt=supplied_receipt,
                )
    with (
        case.account.write_transaction() as later,
        pytest.raises(ContinuousObservedHoldSourceError, match="POST_PUBLICATION_RECHECK"),
    ):
        reader.recheck_observed_hold_sources_after_publication_in_transaction(
            later, resolved, prepared_account=prepared, account_receipt=receipt
        )


def test_actual_other_publication_cannot_authorize_fresh_source(case):
    reader = resolver(case)
    _, resolved, _ = _prepare_publication(case, reader)
    other = retain(case, reader, name="different-original-source")
    prepared = case.account.prepare(
        other.transition,
        scope=case.base.scope,
        previous=other.previous,
        source_evidence=other.inputs.source.venue_capture,
    )
    with case.account.write_transaction() as connection:
        receipt = case.account.commit_in_transaction(
            connection, prepared=prepared, fence=case.base.h.lease.fence
        )
        with pytest.raises(ContinuousObservedHoldSourceError, match="PENDING_PUBLICATION_DIFFERS"):
            reader.recheck_observed_hold_sources_after_publication_in_transaction(
                connection, resolved, prepared_account=prepared, account_receipt=receipt
            )


def test_actual_post_publication_preserves_historical_sources_with_later_parent(case):
    reader = resolver(case)
    original = retain(case, reader)
    publish(case, original)
    applications = tuple(a for b in original.inputs.application_batches for a in b.applications)
    reader = resolver(case)
    current = retain(case, reader, name="next-observed-parent", applications=applications)
    plan = reader.prepare_observed_hold_source_read((original.reference, current.reference))
    resolved = reader.resolve_observed_hold_sources(capture(case, reader, plan), admissions=())
    reader.require_resolved(resolved)
    assert resolved.state.captured.historical == (True, False)
    prepared = case.account.prepare(
        current.transition,
        scope=case.base.scope,
        previous=current.previous,
        source_evidence=current.inputs.source.venue_capture,
    )
    with case.account.write_transaction() as connection:
        receipt = case.account.commit_in_transaction(
            connection, prepared=prepared, fence=case.base.h.lease.fence
        )
        reader.recheck_observed_hold_sources_after_publication_in_transaction(
            connection, resolved, prepared_account=prepared, account_receipt=receipt
        )
    assert resolved.inputs[0].source.checked_at == original.inputs.source.checked_at
    assert resolved.inputs[1].source.checked_at == current.inputs.source.checked_at


def test_repeated_actual_capture_interns_owned_venue_before_page_reads(case, monkeypatch):
    reader = resolver(case)
    original = retain(case, reader)
    previous = original.previous
    frontier = project_continuous_venue_frontier(
        checkpoint=previous.checkpoint,
        capture=original.venue.capture,
        prior_applications=(
            continuous_initial_cash_application(previous.checkpoint, accounting=case.accounting),
        ),
        frontier_id="same-capture-second-preparation",
        admitted_at=original.inputs.frontier.knowledge_at + timedelta(seconds=1),
    )
    transition = case.base.owner.prepare_frontier(
        command_id="same-capture-second-preparation",
        checkpoint=previous.checkpoint,
        frontier=frontier,
    )
    case.base.h.clock.instant = frontier.knowledge_at
    second = reader.retain_source(
        previous=previous,
        transition=transition,
        venue=original.venue,
        current=case.base.h.resolved(),
    )
    assert second.inputs.source.venue_capture == original.inputs.source.venue_capture
    resolve_venue = case.sources.resolve
    read_object = case.base.artifacts.read
    resolutions, reads = [], []

    def counted_resolve(captured):
        resolutions.append(captured)
        return resolve_venue(captured)

    def counted_read(reference, *, max_bytes):
        reads.append(reference)
        return read_object(reference, max_bytes=max_bytes)

    monkeypatch.setattr(case.sources, "resolve", counted_resolve)
    monkeypatch.setattr(case.base.artifacts, "read", counted_read)
    plan = reader.prepare_observed_hold_source_read((original.reference, second.reference))
    assert resolutions == [original.venue.capture]
    assert plan.state.venues[0] is plan.state.venues[1]
    assert len(reads) == len(set(reads))
    for page in original.venue.capture.manifest.sources:
        assert reads.count(page.evidence.object_ref) == 1
    resolved = reader.resolve_observed_hold_sources(capture(case, reader, plan), admissions=())
    assert resolved.inputs == (original.inputs, second.inputs)


@pytest.mark.parametrize("changed", ["original_journal", "original_lease", "parent", "deadline"])
def test_actual_post_publication_rechecks_original_rows_and_current_fence(case, changed):
    from packages.persistence.durable_journal_schema import journal_entries
    from packages.persistence.schema import phase2_account_leases

    reader = resolver(case)
    token, resolved, prepared = _prepare_publication(case, reader)
    with pytest.raises(ContinuousObservedHoldSourceError), case.account.write_transaction() as conn:
        receipt = case.account.commit_in_transaction(
            conn, prepared=prepared, fence=case.base.h.lease.fence
        )
        if changed == "original_journal":
            source = token.venue.capture.manifest.sources[0]
            conn.execute(
                sa.update(journal_entries)
                .where(journal_entries.c.key_sha256 == source.key.semantic_sha256)
                .values(payload=b"changed")
            )
        elif changed == "original_lease":
            conn.execute(
                sa.update(phase2_account_leases)
                .where(
                    phase2_account_leases.c.lease_sha256 == token.inputs.source.fence.lease_sha256
                )
                .values(owner_id="different-owner")
            )
        elif changed == "parent":
            conn.execute(
                sa.update(continuous_account_commits)
                .where(
                    continuous_account_commits.c.command_id
                    == token.inputs.source.coordinator_command_id
                )
                .values(checkpoint_sha256="d" * 64)
            )
        else:
            case.base.h.clock.instant = token.inputs.source.valid_until
        reader.recheck_observed_hold_sources_after_publication_in_transaction(
            conn, resolved, prepared_account=prepared, account_receipt=receipt
        )
    with case.base.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(continuous_account_commits))
            == 1
        )
