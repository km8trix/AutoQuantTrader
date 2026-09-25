"""Actual local C/B/A lineage with repository fixtures; no provider or send authority."""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.persistence.continuous_runtime_attempt_sources import (
    ContinuousRuntimeAttemptSourceError,
    PreparedContinuousRuntimeAttemptSource,
    SqlContinuousRuntimeAttemptSources,
)
from packages.persistence.daily_runtime_risk import RuntimeReadBudget
from tests.integration.test_continuous_runtime_sources import (
    CLOCK_SCHEMA,
    FORWARD_CLOSURE_SCHEMA,
    RUNTIME_SOURCE_SCHEMA,
    Case,
    ContinuousRuntimeSourceDescriptor,
    RuntimeClockObservation,
    SqlContinuousRuntimeSources,
    SqlDurableJournal,
    SqlRuntimeOperatingEvidence,
    VenueSourceReference,
    _write_transaction,
    codec,
    empty_head,
    healthy_sampler,
    install_producers,
    modeled_daily_availability,
    project_continuous_daily_frontier,
)


@pytest.fixture
def attempt_case(tmp_path, monkeypatch):
    from decimal import Decimal

    # The same A fixture uses an actual retained daily bootstrap here.
    import tests.integration.test_continuous_reconciliation_publication as publication_fixture
    from packages.domain.stateful_venue_contracts import VenueCommand, VenueRunDue
    from packages.domain.venue_reconciliation_contracts import VenueCaptureRequest
    from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
    from tests.integration.test_continuous_reconciliation_publication import PublicationCase
    from tests.integration.test_venue_reconciliation_capture import Clock as VenueClock

    monkeypatch.setattr(
        publication_fixture, "Case", lambda path, **kwargs: Case(path, captured=True)
    )
    paired = PublicationCase(tmp_path)
    case = paired.base
    install_producers(case, paired.model)
    try:
        session = case.inputs.spec.window.scored_sessions[0]
        at = modeled_daily_availability(session) + timedelta(milliseconds=50)
        case.h.coordinator.release(case.h.lease.fence)
        case.h.clock.instant = at - timedelta(seconds=10)
        case.h.decision_at = at
        case.h.lease = case.h.coordinator.acquire("owner")
        paired.restart()
        prior = None
        for index, seconds in enumerate((7, 4)):
            observed = at - timedelta(seconds=seconds)
            paired.venue.execute(
                VenueCommand(f"venue-observed-tick-{index}", observed, VenueRunDue())
            )
            venue = paired.venue.read()
            capture = SqlVenueReconciliationCapture(
                case.engine, artifacts=case.artifacts, codec=codec, clock=VenueClock(observed)
            ).capture(
                VenueCaptureRequest(
                    f"cash-round-{index}",
                    paired.binding,
                    case.inputs.spec.initialized_at,
                    venue.state.as_of,
                ),
                venue=paired.venue,
            )
            prepared_pair = paired.prepare(f"cash-round-{index}", previous=prior, capture=capture)
            paired.publisher.publish(prepared_pair, fence=case.h.lease.fence)
            prior = paired.restore()
        assert prior.reconciliation.resolved.result.status == "converged"
        publication = case.add_capture(session)
        closure = case.closure(
            "cash-qualified-daily",
            at,
            tuple(item.observation_id for item in publication.record.observations),
        )
        previous = paired.account.restore(case.scope)
        request = project_continuous_daily_frontier(
            checkpoint=previous.checkpoint,
            source_state=case.source_state,
            observation_ids=closure.observation_ids,
            frontier_id=closure.closure_id,
            admitted_at=at,
            benchmark_instrument_id=case.inputs.spec.instruments[0][0],
            capture_evidence_class=closure.evidence_class,
        )
        _clock, sampler, sample = healthy_sampler(case.scope, at=at)
        operating = SqlRuntimeOperatingEvidence(
            case.engine,
            journal=SqlDurableJournal(
                case.engine, codec=codec, record_types={CLOCK_SCHEMA: RuntimeClockObservation}
            ),
            artifacts=case.artifacts,
            codec=codec,
            clock_sampler=sampler,
        )
        clock_append = operating.prepare_clock_append(
            sample, expected_head=empty_head(operating.clock_key())
        )
        with _write_transaction(case.engine) as connection:
            clock_ref = operating.append_clock_in_transaction(connection, clock_append)
        model_ref = VenueSourceReference(
            paired.model.producer,
            paired.model.semantic_sha256,
            case.artifacts.put(codec.encode_record(paired.model)),
        )
        service = SqlContinuousRuntimeSources(
            case.engine,
            coordinator=case.h.coordinator,
            journal=SqlDurableJournal(
                case.engine,
                codec=codec,
                record_types={RUNTIME_SOURCE_SCHEMA: ContinuousRuntimeSourceDescriptor},
            ),
            artifacts=case.artifacts,
            codec=codec,
            forward_sources=case.forward,
            operating=operating,
            accounting=case.owner.accounting,
            strategy=case.owner.strategy,
            venue_model=paired.model,
            venue_reference=model_ref,
            producer_map=case.h.producer_map,
            benchmark_instrument_id=case.inputs.spec.instruments[0][0],
            current_fence=lambda: case.h.lease.fence,
        )
        case.h.store.producers = service
        case.reader = service
        case.owner.runtime_evidence = service
        paired.restart()
        case.store = paired.account
        service.bind_stores(accounts=paired.account, daily=case.h.store)
        service.bind_reconciliation(paired.publisher)
        previous = paired.account.restore(case.scope)
        case.h.clock.instant = at
        prepared = service.prepare_descriptor(
            descriptor_id="actual-cash-source",
            scope=case.scope,
            request=request,
            market_source=case.put(FORWARD_CLOSURE_SCHEMA, closure),
            previous=previous,
            fence=case.h.lease.fence,
            clock_reference=clock_ref,
            request_kind="frontier",
            accounts=paired.account,
            daily=case.h.store,
        )
        with paired.account.write_transaction() as connection:
            service.append_descriptor_in_transaction(connection, prepared, fence=case.h.lease.fence)
        resolved = service.resolve_prepared_descriptor(prepared)
        assert resolved.plan.reconciliation.reconciliation.receipt == prior.reconciliation.receipt
        assert service.evidence_port(resolved).cash_restrictions == Decimal(0)
        transition = case.owner.prepare_frontier(
            command_id="cash-qualified-daily", checkpoint=previous.checkpoint, frontier=request
        )
        (decision,) = transition.new_decisions
        assert decision.evidence.inputs.reconciliation == prior.reconciliation.resolved.result
        assert decision.evidence.inputs.cash_restrictions == 0
        assert decision.evidence.inputs.reconciliation.scope.source_class == "stateful_simulation"
        assert prepared.descriptor.market_evidence_class == "synthetic_fixture"
        assert decision.decision.approved
        admission = case.h.prepare(
            dict(
                command_id="actual-qualified-admission",
                request_sha256=decision.batch.semantic_sha256,
                batch=decision.batch,
                assignment_sha256=case.h.assignment.semantic_sha256,
                input_refs=decision.evidence.inputs,
                prepared_commitments=decision.installed_commitments,
                fence=case.h.lease.fence,
            )
        )
        receipt = case.publish(
            transition, previous, prepared.descriptor.market_source, (admission,)
        )
        restored = case.store.restore(case.scope)
        assert restored.receipt == receipt
        assert restored.checkpoint.state.commitments == transition.checkpoint.state.commitments
        assert len(restored.checkpoint.state.commitments) == len(decision.installed_commitments) > 0
        assert not any("CASH_RESTRICTION" in reason for reason in decision.decision.reasons)
        current = case.h.store.resolve_snapshot(
            case.h.store.read_snapshot(account_id=case.scope.account_id, fence=case.h.lease.fence)
        )
        attempt_reader = SqlContinuousRuntimeAttemptSources(
            case.engine,
            accounts=case.store,
            preparer=case.owner,
            daily=case.h.store,
            runtime_sources=service,
            artifacts=case.artifacts,
            codec=codec,
        )
        service.bind_attempt_sources(attempt_reader)
        view = case.h.store.inspect_prepared_admission(admission)
        case.paired_fixture = paired
        yield case, service, attempt_reader, restored, current, view
    finally:
        paired.close()


def pending(attempt_case, *, command="actual-pending"):
    _case, _service, reader, previous, current, view = attempt_case
    prepared = reader.retain_pending(
        coordinator_command_id=command, previous=previous, current=current, admissions=(view,)
    )
    return prepared


def publish_original_pending(attempt_case):
    from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication

    case, _service, _reader, previous, _current, _view = attempt_case
    source = pending(attempt_case, command="pending-before-reconciliation")
    requested = case.h.store.resolve_snapshot(
        case.h.store.read_attempt_snapshot(
            account_id=case.scope.account_id,
            fence=case.h.lease.fence,
            envelopes=source.envelopes,
            preparations=source.closure.preparations,
        )
    )
    mutation = case.h.store.prepare_attempt_mutation(requested)
    transition = case.owner.prepare_runtime_action(
        command_id=source.source.coordinator_command_id,
        checkpoint=previous.checkpoint,
        action=source.action,
    )
    prepared = case.store.prepare(
        transition,
        scope=case.scope,
        previous=previous,
        source_evidence=source.reference,
        attempts=mutation,
    )
    receipt = SqlContinuousAttemptPublication(account=case.store).publish(
        prepared, fence=case.h.lease.fence
    )
    return source, prepared, receipt


@pytest.mark.parametrize("tamper", [None, "original_b", "original_c", "published_c"])
def test_actual_reconciliation_after_pending_keeps_exact_paired_history(
    attempt_case, monkeypatch, tamper
):
    import sqlalchemy as sa

    from packages.persistence.continuous_account_schema import continuous_account_commits
    from packages.persistence.daily_runtime_risk_schema import daily_runtime_attempt_events

    case, _service, _reader, _previous, _current, _view = attempt_case
    source, pending_account, pending_receipt = publish_original_pending(attempt_case)
    paired = case.paired_fixture
    prior = paired.restore()
    prepared = paired.prepare("actual-a-after-pending", previous=prior)
    before = paired.counts()
    if tamper is not None:
        commit = case.store.commit_in_transaction

        def changed(connection, **kwargs):
            receipt = commit(connection, **kwargs)
            if tamper == "original_b":
                count = connection.execute(
                    sa.update(daily_runtime_attempt_events)
                    .where(
                        daily_runtime_attempt_events.c.account_id == case.scope.account_id,
                        daily_runtime_attempt_events.c.attempt_id
                        == source.envelopes[0].event.attempt_id,
                    )
                    .values(event_id="changed-original-pending")
                ).rowcount
            else:
                command_id = (
                    pending_account.commit.transition.command_id
                    if tamper == "original_c"
                    else prepared.continuous.commit.transition.command_id
                )
                count = connection.execute(
                    sa.update(continuous_account_commits)
                    .where(
                        continuous_account_commits.c.account_id == case.scope.account_id,
                        continuous_account_commits.c.command_id == command_id,
                    )
                    .values(canonical_payload=b"{}")
                ).rowcount
            assert count == 1
            return receipt

        monkeypatch.setattr(case.store, "commit_in_transaction", changed)
        with pytest.raises(ValueError, match=r"changed|CHANGED|DIFFER"):
            paired.publisher.publish(prepared, fence=case.h.lease.fence)
        assert paired.counts() == before
        assert case.store.restore(case.scope).receipt == pending_receipt
        assert paired.restore().reconciliation.receipt == prior.reconciliation.receipt
        return
    active = set()
    hooks = (
        ("begin", lambda connection: active.add(id(connection))),
        ("commit", lambda connection: active.discard(id(connection))),
        ("rollback", lambda connection: active.discard(id(connection))),
    )
    for event, hook in hooks:
        sa.event.listen(case.engine, event, hook)

    def guard(original):
        def checked(*args, **kwargs):
            assert not active, "heavy source graph work inside paired account SQL"
            return original(*args, **kwargs)

        return checked

    try:
        with monkeypatch.context() as guarded:
            for name in ("encode_record", "decode_record"):
                guarded.setattr(codec, name, guard(getattr(codec, name)))
            for name in ("read", "put"):
                guarded.setattr(case.artifacts, name, guard(getattr(case.artifacts, name)))
            receipt = paired.publisher.publish(prepared, fence=case.h.lease.fence)
    finally:
        for event, hook in hooks:
            sa.event.remove(case.engine, event, hook)
    assert case.store.restore(case.scope).receipt == receipt.continuous
    assert paired.restore().reconciliation.receipt == receipt.reconciliation
    assert case.h.resolved().attempts[0].state.value == "pending"


def test_original_pending_source_reads_without_recursive_restore(attempt_case, monkeypatch):
    case, _service, reader, previous, current, view = attempt_case
    prepared = pending(attempt_case)
    assert type(prepared) is PreparedContinuousRuntimeAttemptSource
    assert prepared.action.command is None
    assert prepared.action.attempt_events == prepared.closure.events
    assert prepared.source.checked_at == current.raw.receipt.validated_at
    assert prepared.closure.previous == previous.receipt
    assert all(event.state.value == "pending" for event in prepared.closure.events)
    reader.require_prepared(prepared)
    monkeypatch.setattr(case.store, "restore", lambda *a, **k: pytest.fail("recursive C restore"))
    plan = reader.prepare_attempt_source_read((prepared.reference,))
    budget = RuntimeReadBudget()
    with case.store.write_transaction() as connection:
        raw = reader.capture_attempt_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=budget
        )
    resolved = reader.resolve_attempt_sources(raw, admissions=(view,))
    reader.require_resolved(resolved)
    assert resolved.sources == (prepared.source,)
    assert budget.payload_bytes > 0
    with case.store.write_transaction() as connection:
        reader.recheck_attempt_sources_in_transaction(connection, resolved)


def test_inspect_dispatch_keys_requires_original_prefix_and_known_bounded_ids(attempt_case):
    case, _service, reader, _previous, _current, _admission = attempt_case
    source, _prepared, _receipt = publish_original_pending(attempt_case)
    previous, current = case.store.restore(case.scope), case.h.resolved()
    attempt_id = source.closure.preparations[0].attempt_id
    keys = reader.inspect_dispatch_keys(
        previous=previous, current=current, attempt_ids=(attempt_id,)
    )
    assert len(keys) == 1
    assert reader.dispatch_journal.read_head(keys[0]) == empty_head(keys[0])
    assert keys[0].account_scope == case.scope.account_id
    for identifiers in (
        (),
        (attempt_id, attempt_id),
        ("missing",),
        ("x" * 129,),
        (attempt_id,) * 5,
    ):
        with pytest.raises(ValueError):
            reader.inspect_dispatch_keys(
                previous=previous, current=current, attempt_ids=identifiers
            )
    with pytest.raises(ValueError):
        reader.inspect_dispatch_keys(
            previous=replace(previous), current=current, attempt_ids=(attempt_id,)
        )
    with pytest.raises(ValueError):
        reader.inspect_dispatch_keys(
            previous=previous, current=replace(current), attempt_ids=(attempt_id,)
        )
    assert case.h.resolved().attempts == current.attempts
    assert case.store.restore(case.scope).checkpoint == previous.checkpoint


def test_copied_preparation_and_reference_without_owner_cannot_mint_source(
    attempt_case, monkeypatch
):
    from packages.persistence.continuous_runtime_attempt_sources import _Graph

    case, service, reader, _previous, _current, _view = attempt_case
    prepared = pending(attempt_case)
    graph = _Graph(case.artifacts, codec)
    graph.read(prepared.reference, type(prepared.source), prepared.reference.schema_id)
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OBJECT_IDENTITY_CONFLICT"):
        graph.read(
            replace(
                prepared.reference,
                object_ref=replace(
                    prepared.reference.object_ref,
                    byte_count=prepared.reference.object_ref.byte_count + 1,
                ),
            ),
            type(prepared.source),
            prepared.reference.schema_id,
        )
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
        reader.require_prepared(replace(prepared))
    with monkeypatch.context() as guard:
        guard.setattr(
            reader,
            "dispatch_journal",
            SqlDurableJournal(
                case.engine, codec=codec, record_types={CLOCK_SCHEMA: RuntimeClockObservation}
            ),
        )
        with pytest.raises(ContinuousRuntimeAttemptSourceError, match="BOUND_OWNERS_CHANGED"):
            reader.require_prepared(prepared)
        with pytest.raises(ContinuousRuntimeAttemptSourceError, match="BOUND_OWNERS_CHANGED"):
            reader.prepare_attempt_source_read((prepared.reference,))
    stranger = SqlContinuousRuntimeAttemptSources(
        case.engine,
        accounts=case.store,
        preparer=case.owner,
        daily=case.h.store,
        runtime_sources=service,
        artifacts=case.artifacts,
        codec=codec,
    )
    plan = stranger.prepare_attempt_source_read((prepared.reference,))
    with (
        case.store.write_transaction() as connection,
        pytest.raises(ContinuousRuntimeAttemptSourceError, match="ACTUAL_PARENT_OR_FRESH"),
    ):
        stranger.capture_attempt_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )


def test_pending_uses_advancing_actual_clock_without_extending_admission(attempt_case):
    case, _service, reader, previous, _current, view = attempt_case
    case.h.clock.instant += timedelta(milliseconds=10)
    current = case.h.store.resolve_snapshot(
        case.h.store.read_snapshot(account_id=case.scope.account_id, fence=case.h.lease.fence)
    )
    prepared = reader.retain_pending(
        coordinator_command_id="later-pending",
        previous=previous,
        current=current,
        admissions=(view,),
    )
    assert prepared.source.checked_at > previous.checkpoint.now
    assert prepared.source.checked_at == current.raw.receipt.validated_at
    assert prepared.source.valid_until <= view.admission.expires_at
    assert all(event.recorded_at == prepared.source.checked_at for event in prepared.closure.events)
    assert all(
        item.prepared_at == prepared.source.checked_at for item in prepared.closure.preparations
    )
    transition = case.owner.prepare_runtime_action(
        command_id="later-pending", checkpoint=previous.checkpoint, action=prepared.action
    )
    assert transition.checkpoint.now == prepared.source.checked_at
    assert transition.checkpoint.state == previous.checkpoint.state


def test_owned_plan_capture_resolution_and_sql_have_separate_guards(attempt_case, monkeypatch):
    case, _service, reader, _previous, _current, view = attempt_case
    prepared = pending(attempt_case)
    plan = reader.prepare_attempt_source_read((prepared.reference,))
    with (
        case.store.write_transaction() as connection,
        pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"),
    ):
        reader.capture_attempt_sources_in_transaction(
            connection, replace(plan), account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )
    with case.store.write_transaction() as connection:
        raw = reader.capture_attempt_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
        reader.resolve_attempt_sources(replace(raw), admissions=(view,))
    resolved = reader.resolve_attempt_sources(raw, admissions=(view,))
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
        reader.require_resolved(replace(resolved))
    reader.require_resolved(resolved)
    with monkeypatch.context() as guard:

        def fail(*args, **kwargs):
            pytest.fail("heavy operation inside final SQL")

        guard.setattr(codec, "encode_record", fail)
        guard.setattr(codec, "decode_record", fail)
        guard.setattr(case.artifacts, "read", fail)
        guard.setattr(case.artifacts, "put", fail)
        guard.setattr(case.store, "restore", fail)
        with case.store.write_transaction() as connection:
            reader.recheck_attempt_sources_in_transaction(connection, resolved)
    source = plan.state.sources[0].source
    original = source.valid_until
    object.__setattr__(source, "valid_until", original + timedelta(seconds=1))
    try:
        with (
            case.store.write_transaction() as connection,
            pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"),
        ):
            reader.recheck_attempt_sources_in_transaction(connection, resolved)
    finally:
        object.__setattr__(source, "valid_until", original)


def test_original_source_rejects_expiry_and_foreign_postpublication_pair(attempt_case):
    case, _service, reader, previous, current, view = attempt_case
    prepared = pending(attempt_case)
    plan = reader.prepare_attempt_source_read((prepared.reference,))
    with case.store.write_transaction() as connection:
        raw = reader.capture_attempt_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )
    resolved = reader.resolve_attempt_sources(raw, admissions=(view,))
    with (
        case.store.write_transaction() as connection,
        pytest.raises(ContinuousRuntimeAttemptSourceError, match="EXACT_ACCOUNT_PUBLICATION"),
    ):
        reader.recheck_attempt_sources_after_publication_in_transaction(
            connection, resolved, prepared_account=object(), account_receipt=previous.receipt
        )
    case.h.clock.instant = view.admission.expires_at
    later = case.h.store.resolve_snapshot(
        case.h.store.read_snapshot(account_id=case.scope.account_id, fence=case.h.lease.fence)
    )
    with pytest.raises(ValueError):
        reader.retain_pending(
            coordinator_command_id="expired-source",
            previous=previous,
            current=later,
            admissions=(view,),
        )
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="ACTUAL_IN_FLIGHT"):
        reader.retain_unknown(
            coordinator_command_id="invented-unknown",
            previous=previous,
            current=current,
            admissions=(view,),
            attempt_ids=(prepared.closure.preparations[0].attempt_id,),
            reason="unobserved",
            dispatch_keys=(),
        )


def test_complete_graph_admission_counts_unique_objects_before_any_read():
    from packages.domain.research_job_contracts import ObjectRef
    from packages.persistence.continuous_runtime_attempt_sources import (
        MAX_ATTEMPT_OBJECT_BYTES,
        _Graph,
    )

    class Unreadable:
        def read(self, *args, **kwargs):
            pytest.fail("declared complete graph exceeded before object read")

    graph = _Graph(Unreadable(), codec)
    original = ObjectRef("1" * 64, MAX_ATTEMPT_OBJECT_BYTES)
    graph.admit((original, original))
    assert graph.total == MAX_ATTEMPT_OBJECT_BYTES
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="COMPLETE_OBJECT_GRAPH_LIMIT"):
        graph.admit((ObjectRef("2" * 64, 1),))
    captured = ObjectRef("3" * 64, 250, "personal-provider-json/1")
    raw_graph = _Graph(Unreadable(), codec)
    raw_graph.admit((captured, captured))
    assert raw_graph.total == 250
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="TYPED_OBJECT_REQUIRED"):
        raw_graph.raw(captured)
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="COMPLETE_OBJECT_GRAPH_LIMIT"):
        raw_graph.admit((ObjectRef("4" * 64, MAX_ATTEMPT_OBJECT_BYTES),))
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="CODEC_UNSUPPORTED"):
        _Graph(Unreadable(), codec).admit((ObjectRef("5" * 64, 1, "personal-research-dataset-v1"),))


def test_staged_prefix_is_owned_original_provenance_before_financial_replay(attempt_case):
    case, _service, reader, previous, current, view = attempt_case
    original = pending(attempt_case)
    plan = reader.prepare_attempt_source_read((original.reference,))
    with case.store.write_transaction() as connection:
        raw = reader.capture_attempt_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )
    prefix = reader.resolve_original_prefix(
        raw,
        source_reference=original.reference,
        admissions=(view,),
        assignment_sha256=current.assignment.semantic_sha256,
        control_sha256=None if current.control is None else current.control.semantic_sha256,
    )
    reader.require_prefix(prefix)
    assert prefix.reference.receipt == previous.receipt
    assert prefix.checkpoint == previous.checkpoint
    assert prefix.assignment == current.assignment
    assert prefix.control == current.control
    assert prefix.obligations == current.obligations
    assert prefix.attempts == ()
    assert prefix.through_coordinator_sequence == previous.receipt.commit.sequence
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
        reader.require_prefix(replace(prefix))
    with case.store.write_transaction() as connection:
        reader.recheck_prefix_in_transaction(connection, prefix)
    snapshot = prefix.selected[0][0]
    original_rows = snapshot.rows
    object.__setattr__(snapshot, "rows", (*original_rows, {}))
    try:
        with (
            case.store.write_transaction() as connection,
            pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"),
        ):
            reader.recheck_prefix_in_transaction(connection, prefix)
    finally:
        object.__setattr__(snapshot, "rows", original_rows)
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="ASSIGNMENT_PREFIX_MISSING"):
        reader.resolve_original_prefix(
            raw,
            source_reference=original.reference,
            admissions=(view,),
            assignment_sha256="f" * 64,
            control_sha256=None if current.control is None else current.control.semantic_sha256,
        )


def test_historical_source_requires_original_actual_parent_rows(attempt_case, monkeypatch):
    import sqlalchemy as sa

    from packages.persistence.continuous_account_schema import continuous_account_commits
    from packages.persistence.daily_runtime_risk_schema import daily_runtime_attempt_events

    case, service, reader, previous, _current, view = attempt_case
    original = pending(attempt_case)
    requested = case.h.store.resolve_snapshot(
        case.h.store.read_attempt_snapshot(
            account_id=case.scope.account_id,
            fence=case.h.lease.fence,
            envelopes=original.envelopes,
            preparations=original.closure.preparations,
        )
    )
    assert requested.attempt_sources is not None
    mutation = case.h.store.prepare_attempt_mutation(requested)
    transition = case.owner.prepare_runtime_action(
        command_id=original.source.coordinator_command_id,
        checkpoint=previous.checkpoint,
        action=original.action,
    )
    prepared = case.store.prepare(
        transition,
        scope=case.scope,
        previous=previous,
        source_evidence=original.reference,
        attempts=mutation,
    )
    with case.store.write_transaction() as connection:
        receipt = case.store.commit_in_transaction(
            connection, prepared=prepared, fence=case.h.lease.fence
        )
        case.store.composer.recheck_attempt_publication_in_transaction(
            connection, prepared, receipt, fence=case.h.lease.fence
        )
    with case.store.write_transaction() as connection:
        published_raw = case.store.capture_reference_in_transaction(
            connection,
            scope=case.scope,
            command_id=original.source.coordinator_command_id,
            source_lease_sha256=original.source.fence.lease_sha256,
        )
    publication = case.store.resolve_reference(published_raw)
    committed = service.resolve_committed_attempt_sources(
        requested.attempt_sources, publication=publication
    )
    service.require_committed_attempt_sources(committed)
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
        reader.require_committed_attempt_sources(replace(committed))
    with pytest.raises(ValueError, match="OWNED"):
        reader.resolve_committed_attempt_sources(
            requested.attempt_sources, publication=replace(publication)
        )
    with monkeypatch.context() as guarded:

        def forbidden(*args, **kwargs):
            raise AssertionError("heavy committed source work under SQL")

        guarded.setattr(case.artifacts, "read", forbidden)
        guarded.setattr(codec, "encode_record", forbidden)
        guarded.setattr(codec, "decode_record", forbidden)
        with case.store.write_transaction() as connection:
            service.recheck_committed_attempt_sources_in_transaction(connection, committed)
    restarted = SqlContinuousRuntimeAttemptSources(
        case.engine,
        accounts=case.store,
        preparer=case.owner,
        daily=case.h.store,
        runtime_sources=service,
        artifacts=case.artifacts,
        codec=codec,
    )
    monkeypatch.setattr(case.store, "restore", lambda *a, **k: pytest.fail("recursive C restore"))
    plan = restarted.prepare_attempt_source_read((original.reference,))
    with case.store.write_transaction() as connection:
        raw = restarted.capture_attempt_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )
    historical = restarted.resolve_attempt_sources(raw, admissions=(view,))
    assert historical.sources == (original.source,)
    restarted.require_resolved(historical)
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
        restarted.require_committed_attempt_sources(committed)
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="PREPUBLICATION_SOURCE"):
        restarted.resolve_committed_attempt_sources(historical, publication=publication)
    with case.store.write_transaction() as connection:
        restarted.recheck_attempt_sources_in_transaction(connection, historical)
    with (
        case.store.write_transaction() as connection,
        pytest.raises(ValueError, match=r"changed|CHANGED"),
    ):
        changed = connection.execute(
            sa.update(daily_runtime_attempt_events)
            .where(
                daily_runtime_attempt_events.c.account_id == case.scope.account_id,
                daily_runtime_attempt_events.c.attempt_id == original.envelopes[0].event.attempt_id,
            )
            .values(event_id="tampered-original-event")
        )
        assert changed.rowcount == 1
        restarted.recheck_attempt_sources_in_transaction(connection, historical)
    with (
        case.store.write_transaction() as connection,
        pytest.raises(ValueError, match="REFERENCE_ROWS_CHANGED"),
    ):
        changed = connection.execute(
            sa.update(continuous_account_commits)
            .where(
                continuous_account_commits.c.account_id == case.scope.account_id,
                continuous_account_commits.c.command_id == original.source.coordinator_command_id,
            )
            .values(canonical_payload=b"{}")
        )
        assert changed.rowcount == 1
        reader.recheck_committed_attempt_sources_in_transaction(connection, committed)


def activation_preparation(attempt_case):
    """Advance actual C/A observations, original quote, pending parent and fresh clock."""
    from types import SimpleNamespace
    from zoneinfo import ZoneInfo

    from packages.application.continuous_quote_frontier import project_continuous_quote_frontier
    from packages.application.continuous_venue_frontier import project_continuous_venue_frontier
    from packages.domain.continuous_composition_contracts import VENUE_CAPTURE_CLOSURE_SCHEMA
    from packages.domain.continuous_quote_contracts import (
        CONTINUOUS_QUOTE_CLOSURE_SCHEMA,
        ContinuousQuoteClosure,
        ContinuousQuoteSelection,
    )
    from packages.domain.forward_capture_contracts import CaptureClockSample
    from packages.domain.forward_contracts import ForwardDataState, ForwardRequirement
    from packages.domain.stateful_venue_contracts import VenueCommand, VenueRunDue
    from packages.domain.venue_reconciliation_contracts import VenueCaptureRequest
    from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication
    from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
    from tests.integration.test_continuous_runtime_sources import fresh_reader
    from tests.integration.test_personal_forward_capture_journal import capture, journal
    from tests.integration.test_venue_reconciliation_capture import Clock as VenueClock
    from tests.unit.test_personal_forward_capture import Clock, Transport, quote_body, request

    case, before_service, initial_reader, original, _old_current, admission = attempt_case
    paired = case.paired_fixture
    # PENDING is retained during the original admission's short validity window.
    # Its original preparation then survives until the later execution session.
    case.h.clock.instant += timedelta(milliseconds=10)
    pending_source = initial_reader.retain_pending(
        coordinator_command_id="activation-original-pending",
        previous=original,
        current=case.h.resolved(),
        admissions=(admission,),
    )
    pending_snapshot = case.h.store.resolve_snapshot(
        case.h.store.read_attempt_snapshot(
            account_id=case.scope.account_id,
            fence=case.h.lease.fence,
            envelopes=pending_source.envelopes,
            preparations=pending_source.closure.preparations,
        )
    )
    pending_mutation = case.h.store.prepare_attempt_mutation(pending_snapshot)
    pending_transition = case.owner.prepare_runtime_action(
        command_id=pending_source.source.coordinator_command_id,
        checkpoint=original.checkpoint,
        action=pending_source.action,
    )
    pending_account = case.store.prepare(
        pending_transition,
        scope=case.scope,
        previous=original,
        source_evidence=pending_source.reference,
        attempts=pending_mutation,
    )
    SqlContinuousAttemptPublication(account=case.store).publish(
        pending_account, fence=case.h.lease.fence
    )
    original = case.store.restore(case.scope)
    hold = original.checkpoint.state.commitments[0]
    quote_at = hold.not_before
    cutoff = quote_at + timedelta(milliseconds=300)
    case.h.coordinator.release(case.h.lease.fence)
    case.h.clock.instant = quote_at - timedelta(seconds=10)
    case.h.lease = case.h.coordinator.acquire("owner")
    clock, sampler, sample = healthy_sampler(case.scope, at=cutoff)
    operating = SqlRuntimeOperatingEvidence(
        case.engine,
        journal=SqlDurableJournal(
            case.engine, codec=codec, record_types={CLOCK_SCHEMA: RuntimeClockObservation}
        ),
        artifacts=case.artifacts,
        codec=codec,
        clock_sampler=sampler,
    )
    holder = SimpleNamespace(
        operating=operating,
        accounting=before_service.accounting,
        strategy=before_service.strategy,
        venue_model=before_service.venue_model,
        venue_reference=before_service.venue_reference,
        producer_map=before_service.producer_map,
        benchmark_instrument_id=before_service.benchmark_instrument_id,
    )
    service = fresh_reader(case, holder)
    case.h.store.producers = service
    case.reader = service
    case.owner.runtime_evidence = service
    paired.restart()
    case.store = paired.account
    service.bind_stores(accounts=case.store, daily=case.h.store)
    service.bind_reconciliation(paired.publisher)
    reader = SqlContinuousRuntimeAttemptSources(
        case.engine,
        accounts=case.store,
        preparer=case.owner,
        daily=case.h.store,
        runtime_sources=service,
        artifacts=case.artifacts,
        codec=codec,
    )
    service.bind_attempt_sources(reader)
    case.h.clock.instant = cutoff
    previous = case.store.restore(case.scope)
    session = next(
        item
        for item in case.inputs.spec.calendar.sessions
        if item.session_label == hold.execution_session
    )
    req = request()
    source = replace(req.source, account_scope=case.h.account)
    req = replace(
        req,
        capture_id="activation-real-quote",
        source=source,
        instruments=(replace(req.instruments[0], instrument_id=hold.instrument_id),),
        session=session.session_label,
        session_open=session.opens_at,
        session_close=session.closes_at,
        window_start=session.opens_at,
        window_end=session.closes_at,
        journal_key=replace(
            req.journal_key,
            account_scope=case.h.account,
            source_scope_sha256=source.semantic_sha256,
        ),
    )
    state = ForwardDataState((source,), "recorded")
    stamp = quote_at.astimezone(ZoneInfo("America/New_York")).strftime("%H:%M:%S %Z %m-%d-%Y")
    publication = capture(
        req,
        state,
        journal(case.engine),
        case.artifacts,
        clock=Clock(
            quote_at,
            samples=tuple(
                CaptureClockSample(
                    quote_at + timedelta(milliseconds=n),
                    clock.mono - 300_000_000 + n * 1_000_000,
                    clock.epoch,
                )
                for n in (0, 100, 200)
            ),
        ),
        transport=Transport(
            quote_body(
                dateTimeUTC=int(quote_at.timestamp()),
                All={"bid": 99, "ask": 100, "bidTime": stamp, "askTime": stamp},
            )
        ),
    )
    closure = ContinuousQuoteClosure(
        account_id=case.h.account,
        closure_id="activation-original-quote",
        initial_state=state,
        publications=(publication,),
        selections=(
            ContinuousQuoteSelection(
                publication.record.observations[0].observation_id,
                ForwardRequirement(
                    source.source_id,
                    hold.instrument_id,
                    hold.symbol,
                    session.session_label,
                    "quote",
                ),
                hold.side,
                req.producer,
            ),
        ),
        admitted_at=cutoff,
        boot_id=clock.epoch,
        admitted_monotonic_ns=clock.mono,
        evidence_class="synthetic_fixture",
    )
    market = case.forward.resolve(closure)
    frontier = project_continuous_quote_frontier(
        checkpoint=previous.checkpoint, closure=closure, source_state=market.state
    )
    quote_ref = case.put(CONTINUOUS_QUOTE_CLOSURE_SCHEMA, closure)
    transition = case.owner.prepare_frontier(
        command_id="activation-quote-parent", checkpoint=previous.checkpoint, frontier=frontier
    )
    from packages.persistence.continuous_frontier_publication import (
        SqlContinuousFrontierPublication,
    )

    prepared_quote = case.store.prepare(
        transition, scope=case.scope, previous=previous, source_evidence=quote_ref
    )
    SqlContinuousFrontierPublication(account=case.store).publish(prepared_quote)
    previous = case.store.restore(case.scope)
    clock_append = operating.prepare_clock_append(
        sample, expected_head=operating.journal.read_head(operating.clock_key())
    )
    with case.store.write_transaction() as connection:
        quote_clock = operating.append_clock_in_transaction(connection, clock_append)
    case.h.clock.instant += timedelta(milliseconds=10)
    clock.advance(0.01)
    # PENDING changes the attempt/effect heads. Authenticate new independent A
    # rounds against those exact heads, within the original quote lifetime.
    prior = paired.restore()
    for index in range(2):
        observed = previous.checkpoint.now + timedelta(milliseconds=10)
        paired.venue.execute(VenueCommand(f"pending-venue-tick-{index}", observed, VenueRunDue()))
        venue = paired.venue.read()
        captured = SqlVenueReconciliationCapture(
            case.engine, artifacts=case.artifacts, codec=codec, clock=VenueClock(observed)
        ).capture(
            VenueCaptureRequest(
                f"pending-reconcile-{index}",
                paired.binding,
                case.inputs.spec.initialized_at,
                venue.state.as_of,
            ),
            venue=paired.venue,
        )
        admitted_at = captured.observed.completed_at + timedelta(milliseconds=10)
        venue_frontier = project_continuous_venue_frontier(
            checkpoint=previous.checkpoint,
            capture=captured,
            prior_applications=prior.reconciliation.resolved.applications.applications,
            frontier_id=f"pending-reconcile-{index}",
            admitted_at=admitted_at,
        )
        transition = case.owner.prepare_frontier(
            command_id=venue_frontier.frontier_id,
            checkpoint=previous.checkpoint,
            frontier=venue_frontier,
        )
        clock.advance((admitted_at - case.h.clock.instant).total_seconds())
        case.h.clock.instant = admitted_at
        canonical = case.store.prepare(
            transition,
            scope=case.scope,
            previous=previous,
            source_evidence=case.put(VENUE_CAPTURE_CLOSURE_SCHEMA, captured),
        )
        reconciled = paired.publisher.prepare(canonical, previous=prior)
        paired.publisher.publish(reconciled, fence=case.h.lease.fence)
        prior = paired.restore()
        previous = prior.continuous
    assert prior.reconciliation.resolved.result.status == "converged"
    case.h.clock.instant += timedelta(milliseconds=10)
    clock.advance(0.01)
    sample = sampler.sample()
    clock_append = operating.prepare_clock_append(
        sample, expected_head=operating.journal.read_head(operating.clock_key())
    )
    with case.store.write_transaction() as connection:
        current_clock = operating.append_clock_in_transaction(connection, clock_append)
    descriptor = service.prepare_descriptor(
        descriptor_id="activation-original-descriptor",
        scope=case.scope,
        request=frontier,
        market_source=quote_ref,
        previous=previous,
        fence=case.h.lease.fence,
        clock_reference=current_clock,
        quote_clock_reference=quote_clock,
        request_kind="activation_dependencies",
        accounts=case.store,
        daily=case.h.store,
    )
    with case.store.write_transaction() as connection:
        service.append_descriptor_in_transaction(connection, descriptor, fence=case.h.lease.fence)
    resolved_descriptor = service.resolve_prepared_descriptor(descriptor)
    current = resolved_descriptor.plan.daily
    prepared_source = reader.retain_activation(
        coordinator_command_id="activation-actual-parent",
        previous=previous,
        current=current,
        admissions=(admission,),
        descriptor=resolved_descriptor,
        attempt_ids=tuple(item.attempt_id for item in current.attempts),
    )
    return case, service, reader, previous, current, admission, prepared_source, resolved_descriptor


def test_activation_actual_original_descriptor_and_dispatch_history(attempt_case):
    from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication

    case, service, reader, previous, _current, admission, source, _descriptor = (
        activation_preparation(attempt_case)
    )
    assert source.source.checked_at > previous.checkpoint.now
    assert source.source.checked_at > previous.checkpoint.current.snapshot.point.knowledge_at
    assert all(
        event.event.dispatch.record.activation.snapshot == previous.checkpoint.current.snapshot
        for event in source.envelopes
    )
    raw = case.h.store.read_attempt_snapshot(
        account_id=case.scope.account_id, fence=case.h.lease.fence, envelopes=source.envelopes
    )
    actual = case.h.store.resolve_snapshot(raw)
    mutation = case.h.store.prepare_attempt_mutation(
        actual, dispatch_journal=reader.dispatch_journal, dispatch_appends=source.dispatch_appends
    )
    transition = case.owner.prepare_runtime_action(
        command_id=source.source.coordinator_command_id,
        checkpoint=previous.checkpoint,
        action=source.action,
    )
    account = case.store.prepare(
        transition,
        scope=case.scope,
        previous=previous,
        source_evidence=source.reference,
        attempts=mutation,
    )
    publisher = SqlContinuousAttemptPublication(account=case.store)
    completed = publisher.publish_dispatch(account, fence=case.h.lease.fence)
    publisher.require_completed(completed)
    with pytest.raises(ValueError, match="ORIGINAL_SUCCESSFUL"):
        publisher.require_completed(replace(completed))
    with pytest.raises(ValueError, match="ORIGINAL_SUCCESSFUL"):
        SqlContinuousAttemptPublication(account=case.store).require_completed(completed)
    receipt = completed.receipt
    with case.store.write_transaction() as connection:
        published_raw = case.store.capture_reference_in_transaction(
            connection,
            scope=case.scope,
            command_id=source.source.coordinator_command_id,
            source_lease_sha256=source.source.fence.lease_sha256,
        )
    publication = case.store.resolve_reference(published_raw)
    committed_sources = service.resolve_committed_attempt_sources(
        actual.attempt_sources, publication=publication
    )
    service.require_committed_attempt_sources(committed_sources)
    case.h.store.require_prepared_attempt(mutation)
    with case.store.write_transaction() as connection:
        assert (
            case.h.store.recheck_completed_attempt_in_transaction(
                connection, mutation, fence=case.h.lease.fence, committed_sources=committed_sources
            )
            is mutation.result
        )
    restored = case.store.restore(case.scope)
    assert restored.receipt == receipt
    assert case.h.resolved().attempts == mutation.result.attempts
    assert all(item.state.value == "in_flight" for item in mutation.result.attempts)
    assert restored.checkpoint.state.submissions == previous.checkpoint.state.submissions
    assert restored.checkpoint.state.broker_events == previous.checkpoint.state.broker_events
    assert restored.checkpoint.request_rows[-len(source.dispatch_appends) :] == tuple(
        (source.source.checked_at, True) for _ in source.dispatch_appends
    )
    case.h.clock.instant += timedelta(milliseconds=10)
    current = case.h.resolved()
    assert (
        reader.inspect_dispatch_keys(
            previous=restored,
            current=current,
            attempt_ids=tuple(item.attempt_id for item in current.attempts),
        )
        == source.closure.dispatch_keys
    )
    assert reader._dispatch_prefix(source.closure.dispatch_keys[0], current.attempts) == (
        source.dispatch_appends[-1].receipt.committed_head,
        source.dispatch_appends[-1].receipt,
    )
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="ORIGINAL_PENDING"):
        reader.retain_expired_unsent(
            coordinator_command_id="cannot-release-in-flight",
            previous=restored,
            current=current,
            admissions=(admission,),
            attempt_id=current.attempts[0].attempt_id,
        )
    unknown = reader.retain_unknown(
        coordinator_command_id="actual-unknown-parent",
        previous=restored,
        current=current,
        admissions=(admission,),
        attempt_ids=tuple(item.attempt_id for item in current.attempts),
        reason="independent-ack-unobserved",
        dispatch_keys=source.closure.dispatch_keys,
    )
    assert unknown.action.command is None
    assert tuple(
        item.record.activation.expires_at for item in unknown.closure.prior_dispatches
    ) == (tuple(item.event.dispatch.record.activation.expires_at for item in source.envelopes))
    unknown_snapshot = case.h.store.resolve_snapshot(
        case.h.store.read_attempt_snapshot(
            account_id=case.scope.account_id, fence=case.h.lease.fence, envelopes=unknown.envelopes
        )
    )
    unknown_mutation = case.h.store.prepare_attempt_mutation(unknown_snapshot)
    unknown_transition = case.owner.prepare_runtime_action(
        command_id=unknown.source.coordinator_command_id,
        checkpoint=restored.checkpoint,
        action=unknown.action,
    )
    unknown_account = case.store.prepare(
        unknown_transition,
        scope=case.scope,
        previous=restored,
        source_evidence=unknown.reference,
        attempts=unknown_mutation,
    )
    unknown_receipt = publisher.publish(unknown_account, fence=case.h.lease.fence)
    uncertain = case.store.restore(case.scope)
    assert uncertain.receipt == unknown_receipt
    assert uncertain.checkpoint.state == restored.checkpoint.state
    assert uncertain.checkpoint.current == restored.checkpoint.current
    assert uncertain.checkpoint.request_rows == restored.checkpoint.request_rows
    uncertain_current = case.h.resolved()
    assert all(item.state.value == "unknown" for item in uncertain_current.attempts)
    assert (
        reader.inspect_dispatch_keys(
            previous=uncertain,
            current=uncertain_current,
            attempt_ids=tuple(item.attempt_id for item in uncertain_current.attempts),
        )
        == source.closure.dispatch_keys
    )
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="ORIGINAL_PENDING"):
        reader.retain_expired_unsent(
            coordinator_command_id="cannot-release-unknown",
            previous=uncertain,
            current=uncertain_current,
            admissions=(admission,),
            attempt_id=uncertain_current.attempts[0].attempt_id,
        )


def expired_unsent_preparation(attempt_case):
    """A real independent venue frontier drains scheduled work through original expiry."""
    from packages.domain.stateful_venue_contracts import VenueCommand, VenueRunDue
    from packages.domain.venue_reconciliation_contracts import VenueCaptureRequest
    from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
    from tests.integration.test_continuous_runtime_sources import fresh_reader
    from tests.integration.test_venue_reconciliation_capture import Clock as VenueClock

    case, service, reader, _previous, _current, admission = attempt_case
    pending_source, _prepared, _receipt = publish_original_pending(attempt_case)
    paired = case.paired_fixture
    prior = paired.restore()
    attempt_id = pending_source.closure.preparations[0].attempt_id
    original = case.store.restore(case.scope)
    current = case.h.resolved()
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="ORIGINAL_EXPIRY_NOT_REACHED"):
        reader.retain_expired_unsent(
            coordinator_command_id="too-early-unsent",
            previous=original,
            current=current,
            admissions=(admission,),
            attempt_id=attempt_id,
        )
    expiry = pending_source.closure.preparations[0].original_hold.commitment.expires_at
    case.h.coordinator.release(case.h.lease.fence)
    case.h.clock.instant = expiry - timedelta(seconds=10)
    case.h.lease = case.h.coordinator.acquire("owner")
    case.h.clock.instant = expiry
    unclosed = case.h.resolved()
    if any(
        event.event_id in original.checkpoint.pending_ids and event.knowledge_at <= expiry
        for event in original.checkpoint.events
    ):
        with pytest.raises(ContinuousRuntimeAttemptSourceError, match="SOURCE_FRONTIER_REQUIRED"):
            reader.retain_expired_unsent(
                coordinator_command_id="cannot-cross-original-queue",
                previous=original,
                current=unclosed,
                admissions=(admission,),
                attempt_id=attempt_id,
            )
    # A new lease uses a newly bound exact C/B/source owner graph. The old
    # composer intentionally retains its original fencing generation.
    service = fresh_reader(case, service)
    case.h.store.producers = service
    case.reader = service
    case.owner.runtime_evidence = service
    paired.restart()
    case.store = paired.account
    service.bind_stores(accounts=case.store, daily=case.h.store)
    service.bind_reconciliation(paired.publisher)
    reader = SqlContinuousRuntimeAttemptSources(
        case.engine,
        accounts=case.store,
        preparer=case.owner,
        daily=case.h.store,
        runtime_sources=service,
        artifacts=case.artifacts,
        codec=codec,
    )
    service.bind_attempt_sources(reader)
    prior = paired.restore()
    paired.venue.execute(VenueCommand("unsent-expiry-venue-tick", expiry, VenueRunDue()))
    venue = paired.venue.read()
    captured = SqlVenueReconciliationCapture(
        case.engine, artifacts=case.artifacts, codec=codec, clock=VenueClock(expiry)
    ).capture(
        VenueCaptureRequest(
            "unsent-expiry-source",
            paired.binding,
            case.inputs.spec.initialized_at,
            venue.state.as_of,
        ),
        venue=paired.venue,
    )
    frontier = paired.prepare("unsent-expiry-frontier", previous=prior, capture=captured)
    paired.publisher.publish(frontier, fence=case.h.lease.fence)
    previous = paired.restore().continuous
    current = case.h.resolved()
    source = reader.retain_expired_unsent(
        coordinator_command_id="actual-expired-unsent",
        previous=previous,
        current=current,
        admissions=(admission,),
        attempt_id=attempt_id,
    )
    assert previous.checkpoint.now >= expiry
    assert source.source.checked_at >= expiry
    assert source.closure.unsent_dispatch_head == empty_head(source.closure.dispatch_keys[0])
    return case, service, reader, previous, current, admission, source


@pytest.mark.parametrize("tamper", [None, "dispatch_head", "original_pending"])
def test_actual_expired_unsent_release_publication_restart_and_late_tamper(
    attempt_case, monkeypatch, tamper
):
    import sqlalchemy as sa

    from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication
    from packages.persistence.daily_runtime_risk_schema import daily_runtime_attempt_events
    from packages.persistence.durable_journal_schema import journal_streams

    case, _service, reader, previous, current, admission, source = expired_unsent_preparation(
        attempt_case
    )
    assert source.source.context.approved_snapshot is None
    assert source.source.context.risk_policy_sha256 is None
    assert source.closure.events[0].unsent_proof.attempt_history_sha256 == (
        current.attempts[0].semantic_sha256
    )
    requested = case.h.store.resolve_snapshot(
        case.h.store.read_attempt_snapshot(
            account_id=case.scope.account_id,
            fence=case.h.lease.fence,
            envelopes=source.envelopes,
        )
    )
    mutation = case.h.store.prepare_attempt_mutation(requested)
    transition = case.owner.prepare_runtime_action(
        command_id=source.source.coordinator_command_id,
        checkpoint=previous.checkpoint,
        action=source.action,
    )
    account = case.store.prepare(
        transition,
        scope=case.scope,
        previous=previous,
        source_evidence=source.reference,
        attempts=mutation,
    )
    publisher = SqlContinuousAttemptPublication(account=case.store)
    counts = case.paired_fixture.counts()
    unsent_key = source.closure.dispatch_keys[0]
    unsent_key_payload = codec.encode_record(unsent_key)
    unsent_empty_head = empty_head(unsent_key)
    if tamper is not None:
        original = case.store.commit_in_transaction

        def late_change(connection, **kwargs):
            receipt = original(connection, **kwargs)
            if tamper == "dispatch_head":
                key = source.closure.dispatch_keys[0]
                # An inserted actual stream row must invalidate the captured empty
                # journal even when its logical head is still the empty head.
                changed = connection.execute(
                    sa.insert(journal_streams).values(
                        key_sha256=key.semantic_sha256,
                        key_payload=unsent_key_payload,
                        last_sequence=0,
                        last_entry_sha256=empty_head(key).entry_sha256,
                    )
                )
            else:
                changed = connection.execute(
                    sa.update(daily_runtime_attempt_events)
                    .where(
                        daily_runtime_attempt_events.c.account_id == case.scope.account_id,
                        daily_runtime_attempt_events.c.attempt_id
                        == source.closure.preparations[0].attempt_id,
                        daily_runtime_attempt_events.c.sequence == 1,
                    )
                    .values(event_id="late-original-pending-tamper")
                )
            assert changed.rowcount == 1
            return receipt

        with monkeypatch.context() as guarded:
            guarded.setattr(case.store, "commit_in_transaction", late_change)
            with pytest.raises(ValueError, match=r"CHANGED|changed"):
                publisher.publish(account, fence=case.h.lease.fence)
        assert case.paired_fixture.counts() == counts
        assert case.store.restore(case.scope).receipt == previous.receipt
        assert case.h.resolved().attempts == current.attempts
        return
    receipt = publisher.publish(account, fence=case.h.lease.fence)
    restored = case.store.restore(case.scope)
    assert restored.receipt == receipt
    assert restored.checkpoint.state.commitments[0].state == "terminal"
    assert restored.checkpoint.state.commitments[0].terminal_reason == "runtime_unsent_expired"
    assert restored.checkpoint.state.commitments[0].reserved_cash == 0
    assert restored.checkpoint.state.submissions == previous.checkpoint.state.submissions
    assert restored.checkpoint.state.broker_events == previous.checkpoint.state.broker_events
    assert restored.checkpoint.request_rows == previous.checkpoint.request_rows
    assert all(item.state.value == "abandoned" for item in case.h.resolved().attempts)
    after = case.paired_fixture.counts()
    with pytest.raises(ValueError, match="RESTORE_ORIGINAL_RETRY_REQUIRED"):
        publisher.publish(account, fence=case.h.lease.fence)
    with case.store.write_transaction() as connection:
        assert (
            case.store.retry_in_transaction(
                connection,
                original=restored,
                command_sha256=receipt.commit.transition.command_sha256,
                fence=case.h.lease.fence,
            )
            == receipt
        )
    assert case.paired_fixture.counts() == after
    restarted = SqlContinuousRuntimeAttemptSources(
        case.engine,
        accounts=case.store,
        preparer=case.owner,
        daily=case.h.store,
        runtime_sources=reader.runtime_sources,
        artifacts=case.artifacts,
        codec=codec,
    )
    monkeypatch.setattr(case.store, "restore", lambda *a, **k: pytest.fail("recursive C restore"))
    plan = restarted.prepare_attempt_source_read((source.reference,))
    with case.store.write_transaction() as connection:
        raw = restarted.capture_attempt_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )
    history = restarted.resolve_attempt_sources(raw, admissions=(admission,))
    restarted.require_resolved(history)
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
        restarted.require_resolved(replace(history))
    with monkeypatch.context() as guarded:

        def forbidden(*args, **kwargs):
            raise AssertionError("heavy expired source readback under SQL")

        guarded.setattr(codec, "encode_record", forbidden)
        guarded.setattr(codec, "decode_record", forbidden)
        guarded.setattr(case.artifacts, "read", forbidden)
        guarded.setattr(restarted.dispatch_journal, "capture_in_transaction", forbidden)
        with case.store.write_transaction() as connection:
            restarted.recheck_attempt_sources_in_transaction(connection, history)
            savepoint = connection.begin_nested()
            try:
                changed = connection.execute(
                    sa.insert(journal_streams).values(
                        key_sha256=unsent_key.semantic_sha256,
                        key_payload=unsent_key_payload,
                        last_sequence=0,
                        last_entry_sha256=unsent_empty_head.entry_sha256,
                    )
                )
                assert changed.rowcount == 1
                # Historical zero-length proof owns no subsequently created rows.
                restarted.recheck_attempt_sources_in_transaction(connection, history)
                changed = connection.execute(
                    sa.update(journal_streams)
                    .where(journal_streams.c.key_sha256 == unsent_key.semantic_sha256)
                    .values(key_payload=b"changed actual stream key")
                )
                assert changed.rowcount == 1
                with pytest.raises(ContinuousRuntimeAttemptSourceError, match="IDENTITY_CHANGED"):
                    restarted.recheck_attempt_sources_in_transaction(connection, history)
            finally:
                savepoint.rollback()
            original_head = history.snapshot.plan.state.sources[0].closure.unsent_dispatch_head
            object.__setattr__(original_head, "sequence", 1)
            try:
                with pytest.raises(ContinuousRuntimeAttemptSourceError, match="ORIGINAL"):
                    restarted.recheck_attempt_sources_in_transaction(connection, history)
            finally:
                object.__setattr__(original_head, "sequence", 0)
