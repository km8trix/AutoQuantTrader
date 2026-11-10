"""Actual simulation registration/capture and canonical outcome publication."""

from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa

from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.domain.stateful_venue_contracts import VenueAccept, VenueCommand, VenueReject
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_attempt_outcome_sources import (
    SqlContinuousAttemptOutcomeSources,
)
from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication
from packages.persistence.continuous_runtime_attempt_sources import (
    SqlContinuousRuntimeAttemptSources,
)
from packages.persistence.continuous_simulation_delivery import SqlContinuousSimulationDelivery
from packages.persistence.continuous_venue_sources import SqlContinuousVenueSources
from packages.persistence.daily_runtime_risk import RuntimeReadBudget
from packages.persistence.detached_journal_capture import DetachedJournalCapture
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.stateful_venue import SqlStatefulVenue
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
from tests.integration.test_continuous_runtime_attempt_sources import attempt_case  # noqa: F401
from tests.integration.test_continuous_simulation_delivery import activated_delivery
from tests.integration.test_venue_reconciliation_capture import Clock


def outcome_owner(case, delivery, venue):
    reader = delivery.sources
    runtime = reader.runtime_sources
    scope = ReconciliationScope(
        runtime.venue_model.account_id,
        runtime.venue_model.venue_id,
        "stateful_simulation",
        runtime.venue_reference.semantic_sha256_ref,
        "stateful_simulation",
    )
    capture_clock = Clock(case.h.clock.instant)
    capture = SqlVenueReconciliationCapture(
        case.engine, artifacts=case.artifacts, codec=reader.codec, clock=capture_clock
    )
    venue_sources = SqlContinuousVenueSources(
        case.engine,
        artifacts=case.artifacts,
        codec=reader.codec,
        scope=scope,
        model=runtime.venue_model,
        resolver=case.paired_fixture.sources.resolver,
    )
    helper = SqlContinuousAttemptOutcomeSources(
        attempts=reader, venue=venue, capture=capture, venue_sources=venue_sources
    )
    reader.bind_outcome_sources(helper)
    return helper, capture_clock


def _qualify_outcome(
    case_fixture,
    monkeypatch,
    lost_ack,
    *,
    rejected=False,
):
    case, source, _descriptor, publisher, batch, delivery, venue = activated_delivery(case_fixture)
    reader = delivery.sources
    helper, capture_clock = outcome_owner(case, delivery, venue)
    attempt_id = source.envelopes[0].event.attempt_id
    previous = case.store.restore(case.scope)
    current = case.h.resolved()
    order_id = source.closure.preparations[0].request.submission.order_id
    rejected_command = venue.execute(
        VenueCommand(
            "reject-command-without-registration", case.h.clock.instant, VenueAccept(order_id)
        )
    )
    assert rejected_command.acknowledgment.disposition == "rejected"
    with pytest.raises(ValueError, match="REGISTERED_ORDER_REQUIRED"):
        helper.observe(
            previous=previous, current=current, attempt_id=attempt_id, capture_id="absent"
        )
    if lost_ack:
        execute = venue.execute

        def lost(command, **kwargs):
            execute(command, **kwargs)
            raise OSError("synthetic lost acknowledgment")

        with monkeypatch.context() as guarded:
            guarded.setattr(venue, "execute", lost)
            with pytest.raises(OSError, match="lost acknowledgment"):
                delivery.deliver(batch, source=source, attempt_id=attempt_id)
        unknown = reader.retain_unknown(
            coordinator_command_id="original-lost-ack-unknown",
            previous=previous,
            current=current,
            admissions=source.admissions,
            attempt_ids=(attempt_id,),
            reason="lost_acknowledgment",
            dispatch_keys=source.closure.dispatch_keys,
        )
        publisher.publish(
            publisher.prepare_source(unknown, sources=reader), fence=case.h.lease.fence
        )
        previous = case.store.restore(case.scope)
        current = case.h.resolved()
        assert current.attempts[0].state.value == "unknown"
    else:
        delivery.deliver(batch, source=source, attempt_id=attempt_id)
    unresolved = helper.observe(
        previous=previous, current=current, attempt_id=attempt_id, capture_id="submitted"
    )
    assert unresolved.plan.outcome is None
    with pytest.raises(ValueError, match="DEFINITIVE_ORDER_REQUIRED"):
        reader.retain_outcome(
            coordinator_command_id="not-known",
            previous=previous,
            current=current,
            admissions=source.admissions,
            attempt_id=attempt_id,
            observation=unresolved,
        )
    case.h.clock.instant += timedelta(milliseconds=20)
    accepted = venue.execute(
        VenueCommand(
            "original-known-outcome",
            case.h.clock.instant,
            VenueReject(order_id, "modeled_order_rejection") if rejected else VenueAccept(order_id),
        )
    )
    assert accepted.acknowledgment.disposition == "applied"
    capture_clock.at = case.h.clock.instant
    observation = helper.observe(
        previous=previous, current=current, attempt_id=attempt_id, capture_id="accepted-original"
    )
    assert observation.plan.outcome.order.status == ("rejected" if rejected else "working")
    assert observation.plan.outcome.resolution == ("rejected" if rejected else "accepted")
    assert (
        observation.plan.outcome.observed_at == observation.plan.venue.capture.observed.completed_at
    )
    case.h.clock.instant = capture_clock.at + timedelta(milliseconds=1)
    current = case.h.resolved()
    with pytest.raises(ValueError, match="OWNED_ORIGINAL"):
        helper.require_observation(replace(observation))
    prepared_source = reader.retain_outcome(
        coordinator_command_id="actual-confirmed",
        previous=previous,
        current=current,
        admissions=source.admissions,
        attempt_id=attempt_id,
        observation=observation,
    )
    assert prepared_source.action.command is None
    expected_state = "resolved" if lost_ack else "confirmed"
    assert prepared_source.envelopes[0].event.state.value == expected_state
    plan = reader.prepare_attempt_source_read((prepared_source.reference,))
    with case.store.write_transaction() as connection:
        raw = reader.capture_attempt_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )
    resolved = reader.resolve_attempt_sources(raw, admissions=source.admissions)
    reader.require_resolved(resolved)
    original_outcome = resolved.state.outcomes[0]
    helper.require_resolved(original_outcome)
    if rejected:
        import gc
        import weakref

        from packages.persistence import continuous_runtime_attempt_sources as source_module
        from packages.persistence.daily_runtime_risk import MAX_TOTAL_BYTES, MAX_TOTAL_ROWS

        original_read = reader.artifacts.read
        reads = []

        def bounded_read(reference, **kwargs):
            reads.append(reference)
            return original_read(reference, **kwargs)

        with monkeypatch.context() as guarded:
            guarded.setattr(reader.artifacts, "read", bounded_read)
            guarded.setattr(
                source_module,
                "MAX_ATTEMPT_OBJECT_BYTES",
                observation.plan.reference.object_ref.byte_count + 1,
            )
            with pytest.raises(ValueError, match="OBJECT_GRAPH_LIMIT"):
                helper.prepare(observation.plan.reference, admit_objects=lambda _refs: None)
        assert reads == [observation.plan.reference.object_ref]
        temporary = helper.prepare(observation.plan.reference, admit_objects=lambda _refs: None)
        temporary_id, weak_plan = id(temporary), weakref.ref(temporary)
        del temporary
        gc.collect()
        assert weak_plan() is None
        assert temporary_id not in helper._value_fields
        assert temporary_id not in helper._fields
        with (
            case.store.write_transaction() as connection,
            pytest.raises(ValueError, match="aggregate capture bound"),
        ):
            helper.capture_in_transaction(
                connection,
                observation.plan,
                budget=RuntimeReadBudget(rows=MAX_TOTAL_ROWS),
                journal_pool=DetachedJournalCapture(
                    max_bytes=source_module.MAX_ATTEMPT_OBJECT_BYTES,
                    max_metadata_bytes=source_module.MAX_METADATA_BYTES,
                ),
            )
        # Retain actual source rows once, then reuse the already charged pool.
        # Each later capture still materializes original current/previous C
        # rows, and must charge those copies before any further venue read.
        with case.store.write_transaction() as connection:
            shared_budget = RuntimeReadBudget()
            shared_pool = DetachedJournalCapture(
                max_bytes=source_module.MAX_ATTEMPT_OBJECT_BYTES,
                max_metadata_bytes=source_module.MAX_METADATA_BYTES,
            )
            actual_capture = helper.capture_in_transaction(
                connection,
                observation.plan,
                budget=shared_budget,
                journal_pool=shared_pool,
            )
            copied = tuple(
                index
                for index in (actual_capture.activation.current, actual_capture.activation.previous)
                if index is not None
            )
            copied_bytes = sum(
                case.h.store._row_sizes(continuous_account_commits, index.row)[0]
                for index in copied
            )
            assert len(copied) == 2 and copied_bytes > 0
            assert shared_budget.payload_bytes >= shared_pool.byte_count + copied_bytes
            for limited in (
                RuntimeReadBudget(
                    payload_bytes=MAX_TOTAL_BYTES - copied_bytes + 1,
                    rows=shared_budget.rows,
                    captured=list(shared_budget.captured),
                ),
                RuntimeReadBudget(
                    payload_bytes=shared_budget.payload_bytes,
                    rows=MAX_TOTAL_ROWS - len(copied) + 1,
                    captured=list(shared_budget.captured),
                ),
            ):
                with monkeypatch.context() as guarded:
                    guarded.setattr(
                        helper.venue_sources.journal,
                        "capture_in_transaction",
                        lambda *a, **k: pytest.fail("venue read before charging copied C rows"),
                    )
                    with pytest.raises(ValueError, match="aggregate capture bound"):
                        helper.capture_in_transaction(
                            connection,
                            observation.plan,
                            budget=limited,
                            journal_pool=shared_pool,
                        )
    with pytest.raises(ValueError, match="OWNED_ORIGINAL"):
        helper.require_resolved(replace(original_outcome))
    held = observation.plan.evidence.registration.registration.source_commitment
    original_cash = held.reserved_cash
    object.__setattr__(held, "reserved_cash", original_cash + 1)
    try:
        with pytest.raises(ValueError, match="OWNED_ORIGINAL"):
            helper.require_observation(observation)
    finally:
        object.__setattr__(held, "reserved_cash", original_cash)
    with monkeypatch.context() as guarded:
        guarded.setattr(reader.artifacts, "read", lambda *a, **k: pytest.fail("read before budget"))

        def reject_before_read(_refs):
            raise ValueError("aggregate object budget exhausted")

        with pytest.raises(ValueError, match="aggregate object budget"):
            helper.prepare(observation.plan.reference, admit_objects=reject_before_read)
    with case.store.write_transaction() as connection:
        with monkeypatch.context() as guarded:
            guarded.setattr(reader.codec, "encode_record", lambda *a, **k: pytest.fail("SQL codec"))
            guarded.setattr(reader.codec, "decode_record", lambda *a, **k: pytest.fail("SQL codec"))
            guarded.setattr(reader.artifacts, "read", lambda *a, **k: pytest.fail("SQL object"))
            guarded.setattr(venue, "read", lambda *a, **k: pytest.fail("SQL independent read"))
            helper.recheck_in_transaction(connection, original_outcome)
        with connection.begin_nested() as savepoint:
            original = observation.plan.venue.capture.manifest.sources[0]
            changed = connection.execute(
                sa.update(journal_entries)
                .where(journal_entries.c.key_sha256 == original.key.semantic_sha256)
                .where(journal_entries.c.sequence == original.receipt.committed_head.sequence)
                .values(payload=b"changed-original-capture")
            )
            assert changed.rowcount == 1
            with pytest.raises(ValueError):
                helper.recheck_in_transaction(connection, original_outcome)
            savepoint.rollback()
        helper.recheck_in_transaction(connection, original_outcome)
    prepared = publisher.prepare_source(prepared_source, sources=reader)
    if rejected:
        before_counts = case.paired_fixture.counts()
        original_commit = case.store.commit_in_transaction
        for target in ("capture", "activation"):

            def late_change(connection, _target=target, **kwargs):
                receipt = original_commit(connection, **kwargs)
                if _target == "capture":
                    original = observation.plan.venue.capture.manifest.sources[0]
                    statement = (
                        sa.update(journal_entries)
                        .where(journal_entries.c.key_sha256 == original.key.semantic_sha256)
                        .where(
                            journal_entries.c.sequence == original.receipt.committed_head.sequence
                        )
                        .values(payload=b"late-capture-change")
                    )
                else:
                    statement = (
                        sa.update(continuous_account_commits)
                        .where(continuous_account_commits.c.account_id == case.scope.account_id)
                        .where(
                            continuous_account_commits.c.command_id
                            == observation.plan.evidence.activation.commit.transition.command_id
                        )
                        .values(commit_sha256="f" * 64)
                    )
                assert connection.execute(statement).rowcount == 1
                return receipt

            with monkeypatch.context() as guarded:
                guarded.setattr(case.store, "commit_in_transaction", late_change)
                with pytest.raises(ValueError):
                    publisher.publish(prepared, fence=case.h.lease.fence)
            assert case.paired_fixture.counts() == before_counts
            assert case.h.resolved().attempts[0].state.value == "unknown"
    receipt = publisher.publish(prepared, fence=case.h.lease.fence)
    restored = case.store.restore(case.scope)
    assert restored.receipt == receipt
    assert restored.checkpoint.state == previous.checkpoint.state
    assert restored.checkpoint.current == previous.checkpoint.current
    assert case.h.resolved().attempts[0].state.value == expected_state
    assert case.h.resolved().obligations == current.obligations
    helper.require_resolved(original_outcome)
    with case.store.write_transaction() as connection:
        helper.recheck_in_transaction(connection, original_outcome)
    if rejected:
        restarted = SqlContinuousRuntimeAttemptSources(
            case.engine,
            accounts=case.store,
            preparer=case.owner,
            daily=case.h.store,
            runtime_sources=reader.runtime_sources,
            artifacts=case.artifacts,
            codec=reader.codec,
        )
        restarted_publisher = SqlContinuousAttemptPublication(account=case.store)
        restarted_delivery = SqlContinuousSimulationDelivery(
            publisher=restarted_publisher, sources=restarted
        )
        restarted_venue = SqlStatefulVenue(
            venue.journal._engine,
            model=venue.model,
            artifacts=venue.artifacts,
            codec=venue.codec,
            accounting=venue.accounting,
            verified_sources=restarted_delivery,
        )
        restarted_delivery.bind_venue(restarted_venue)
        restarted_helper, _clock = outcome_owner(case, restarted_delivery, restarted_venue)
        with pytest.raises(ValueError, match="SUCCESSFUL_DISPATCH_COMMIT"):
            restarted_publisher.require_completed(batch)
        with pytest.raises(ValueError, match="OWNED_ORIGINAL"):
            restarted_helper.require_observation(observation)
        with monkeypatch.context() as guarded:
            guarded.setattr(
                case.store, "restore", lambda *a, **k: pytest.fail("recursive C restore")
            )
            guarded.setattr(
                restarted_venue, "read", lambda *a, **k: pytest.fail("historical venue read")
            )
            history_plan = restarted.prepare_attempt_source_read((prepared_source.reference,))
            with case.store.write_transaction() as connection:
                history_raw = restarted.capture_attempt_sources_in_transaction(
                    connection,
                    history_plan,
                    account_id=case.scope.account_id,
                    budget=RuntimeReadBudget(),
                )
            history = restarted.resolve_attempt_sources(history_raw, admissions=source.admissions)
            restarted.require_resolved(history)
            assert history.sources == (prepared_source.source,)
            with case.store.write_transaction() as connection:
                restarted.recheck_attempt_sources_in_transaction(connection, history)


@pytest.mark.parametrize("lost_ack", [False, True])
def test_actual_registration_stays_unresolved_then_original_acceptance_confirms(
    attempt_case,  # noqa: F811
    monkeypatch,
    lost_ack,
):
    _qualify_outcome(attempt_case, monkeypatch, lost_ack)


def test_explicit_rejection_capture_and_late_original_rows_are_atomic(attempt_case, monkeypatch):  # noqa: F811
    _qualify_outcome(attempt_case, monkeypatch, True, rejected=True)
