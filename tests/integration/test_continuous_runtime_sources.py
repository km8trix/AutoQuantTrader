"""Actual local C/B/journal replay with synthetic captures and modeled clock.

Owner assignment is installed through the existing explicitly synthetic fixture;
this suite does not qualify a provider or authorize an external order.
"""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.application import personal_codec as codec
from packages.application.causal_engine import advance_continuous_engine
from packages.application.continuous_source_events import project_continuous_daily_frontier
from packages.domain.continuous_composition_contracts import FORWARD_CLOSURE_SCHEMA
from packages.domain.continuous_runtime_source_contracts import (
    RUNTIME_SOURCE_SCHEMA,
    ContinuousRuntimeSourceDescriptor,
    runtime_producer_map,
)
from packages.domain.daily_runtime_contracts import RuntimeProducerSpec
from packages.domain.durable_journal_contracts import empty_head
from packages.domain.research_dataset import modeled_daily_availability
from packages.domain.runtime_operating_contracts import CLOCK_SCHEMA, RuntimeClockObservation
from packages.domain.stateful_venue_contracts import VenueSourceReference
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.runtime_operating_evidence import SqlRuntimeOperatingEvidence
from tests.integration.test_continuous_composition import Case
from tests.unit.test_runtime_operating_evidence import healthy_sampler
from tests.unit.test_stateful_venue import model


def install_producers(case, venue):
    """Explicit fixture owner installation of the actual source/policy map."""
    daily = case.template
    case.h.producer_map = runtime_producer_map(
        account_id=case.h.account,
        venue_model=venue,
        daily=RuntimeProducerSpec(
            role="daily_inputs",
            producer=daily.producer,
            provider_id=daily.source.provider,
            source_environment=daily.source.environment,
            account_scope=case.h.account,
        ),
        quotes=RuntimeProducerSpec(
            role="quotes",
            producer=daily.producer,
            provider_id="etrade",
            source_environment="production",
            account_scope=case.h.account,
        ),
    )
    before = case.h.assignment
    case.h.install(
        replace(
            before,
            generation=before.generation + 1,
            previous_assignment_sha256=before.semantic_sha256,
            producer_map_sha256=case.h.producer_map.semantic_sha256,
        )
    )


@pytest.fixture
def source(tmp_path):
    case = Case(tmp_path)
    venue = model(
        initial_cash_flow=case.first.checkpoint.state.cash_flows[0],
        instruments=case.first.checkpoint.inputs.spec.instruments,
        execution_policy=replace(
            case.first.checkpoint.inputs.spec.execution_policy, model_id="stateful-venue-facts-v1"
        ),
    )
    install_producers(case, venue)
    case.publish()
    session = case.inputs.spec.window.scored_sessions[0]
    publication = case.add_capture(session)
    at = modeled_daily_availability(session) + timedelta(milliseconds=50)
    case.h.coordinator.release(case.h.lease.fence)
    case.h.clock.instant = at
    case.h.decision_at = at
    case.h.lease = case.h.coordinator.acquire("owner")
    case.store = case.new_store()
    previous = case.store.restore(case.scope)
    closure = case.closure(
        "source-first-close", at, tuple(o.observation_id for o in publication.record.observations)
    )
    request = project_continuous_daily_frontier(
        checkpoint=previous.checkpoint,
        source_state=case.source_state,
        observation_ids=closure.observation_ids,
        frontier_id=closure.closure_id,
        admitted_at=closure.admitted_at,
        benchmark_instrument_id=case.inputs.spec.instruments[0][0],
        capture_evidence_class=closure.evidence_class,
    )
    clock, sampler, sample = healthy_sampler(case.scope, at=at)
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
    venue_ref = VenueSourceReference(
        venue.producer, venue.semantic_sha256, case.artifacts.put(codec.encode_record(venue))
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
        venue_model=venue,
        venue_reference=venue_ref,
        producer_map=case.h.producer_map,
        benchmark_instrument_id=case.inputs.spec.instruments[0][0],
        current_fence=lambda: case.h.lease.fence,
    )
    case.h.store.producers = service
    case.reader = service
    case.owner.runtime_evidence = service
    case.store = case.new_store()
    service.bind_stores(accounts=case.store, daily=case.h.store)
    previous = case.store.restore(case.scope)
    prepared = service.prepare_descriptor(
        descriptor_id="source-before-decision",
        scope=case.scope,
        request=request,
        market_source=case.put(FORWARD_CLOSURE_SCHEMA, closure),
        previous=previous,
        fence=case.h.lease.fence,
        clock_reference=clock_ref,
        request_kind="frontier",
        accounts=case.store,
        daily=case.h.store,
    )
    with case.store.write_transaction() as connection:
        service.append_descriptor_in_transaction(connection, prepared, fence=case.h.lease.fence)
    resolved = service.resolve_prepared_descriptor(prepared)
    yield case, service, previous, request, prepared, resolved, clock
    case.engine.dispose()


def test_actual_original_descriptor_precedes_sole_engine_callback(source):
    _case, service, previous, request, prepared, resolved, _ = source
    assert resolved.descriptor.receipt == prepared.append.receipt
    result = advance_continuous_engine(
        previous.checkpoint,
        request,
        expected_sha256=previous.checkpoint.semantic_sha256,
        accounting=service.accounting,
        strategy=service.strategy,
        runtime_evidence=service.evidence_port(resolved),
    )
    assert len(result.runtime_decisions) == 1
    decision = result.runtime_decisions[0]
    assert decision.evidence.inputs.cash_restrictions is None
    assert decision.evidence.inputs.reconciliation is None
    assert all(
        s.source_sha256 == prepared.descriptor.semantic_sha256
        for s in decision.evidence.inputs.sources
    )
    assert not result.state.commitments


def actual_decision(source):
    _case, service, previous, request, _prepared, resolved, _ = source
    result = advance_continuous_engine(
        previous.checkpoint,
        request,
        expected_sha256=previous.checkpoint.semantic_sha256,
        accounting=service.accounting,
        strategy=service.strategy,
        runtime_evidence=service.evidence_port(resolved),
    )
    return result.runtime_decisions[-1]


def prepare_admission(source, command="verified-blocked-admission"):
    case, _service, _previous, _request, _descriptor, _resolved, _ = source
    decision = actual_decision(source)
    prepared = case.h.prepare(
        dict(
            command_id=command,
            request_sha256=decision.batch.semantic_sha256,
            batch=decision.batch,
            assignment_sha256=case.h.assignment.semantic_sha256,
            input_refs=decision.evidence.inputs,
            prepared_commitments=decision.installed_commitments,
            fence=case.h.lease.fence,
        )
    )
    return prepared


def test_actual_daily_store_independently_replays_the_same_original_callback(source):
    case, _service, *_ = source
    prepared = prepare_admission(source)
    assert prepared.result.decision == actual_decision(source).decision
    assert not prepared.result.decision.approved
    with case.store.write_transaction() as connection:
        result = case.h.store.admit_prepared_in_transaction(
            connection, prepared, fence=case.h.lease.fence
        )
    assert result == prepared.result


def test_original_source_roles_do_not_invent_quotes_or_refresh_control_time(source):
    case, _service, previous, _request, prepared, resolved, _ = source
    decision = actual_decision(source)
    sources = {value.spec.role: value for value in decision.evidence.inputs.sources}
    assert "quotes" not in sources and "cash" not in sources and "reconciliation" not in sources
    assert sources["controls"].source_at == case.h.control.decided_at
    assert sources["account"].source_at == previous.checkpoint.now
    assert sources["account"].received_at == previous.receipt.recorded_at
    assert sources["account"].valid_until == prepared.descriptor.captured_fence.valid_until
    assert sources["daily_inputs"].received_at == max(
        publication.record.receipt.validated_at
        for publication in resolved.plan.market.closure.publications
    )


@pytest.mark.parametrize("token", ["prepared", "resolved", "previous"])
def test_copied_tokens_never_become_source_authority(source, token):
    case, service, previous, _request, prepared, resolved, _ = source
    with pytest.raises(ValueError):
        if token == "prepared":
            with case.store.write_transaction() as connection:
                service.append_descriptor_in_transaction(
                    connection, replace(prepared), fence=case.h.lease.fence
                )
        elif token == "resolved":
            service.evidence_port(replace(resolved))
        else:
            service.prepare_admission_source_read(
                prepared.reference, record_sha256="1" * 64, previous=replace(previous)
            )


def test_clock_expiry_rejects_current_recheck_without_refreshing_original_sources(source):
    case, service, _previous, _request, prepared, resolved, clock = source
    original = codec.encode_record(prepared.descriptor)
    clock.advance(30)
    with pytest.raises(ValueError), case.store.write_transaction() as connection:
        service.recheck_descriptor_in_transaction(connection, resolved, require_current=True)
    assert codec.encode_record(prepared.descriptor) == original


def test_actual_continuous_and_daily_publication_restore_original_source(source):
    case, _service, previous, request, descriptor, _resolved, _ = source
    transition = case.owner.prepare_frontier(
        command_id="actual-source-close", checkpoint=previous.checkpoint, frontier=request
    )
    admission = prepare_admission(source)
    receipt = case.publish(transition, previous, descriptor.descriptor.market_source, (admission,))
    restored = case.store.restore(case.scope)
    assert restored.receipt == receipt
    assert (
        restored.checkpoint.runtime_decisions[-1].decision == transition.new_decisions[-1].decision
    )
    assert restored.checkpoint.state.commitments == ()
    assert (
        restored.receipt.commit.decision_evidence.schema_id == "continuous-composition-evidence/1"
    )


def test_sql_capture_and_final_recheck_never_call_codec_objects_or_accounting(source, monkeypatch):
    from packages.persistence.daily_runtime_risk import RuntimeReadBudget
    from packages.persistence.database import _repeatable_read_transaction

    case, service, _previous, _request, _prepared, resolved, _ = source
    decision = actual_decision(source)

    def forbidden(*args, **kwargs):
        raise AssertionError("heavy work under SQL")

    with monkeypatch.context() as guard:
        guard.setattr(codec, "decode_record", forbidden)
        guard.setattr(codec, "encode_record", forbidden)
        guard.setattr(service.artifacts, "read", forbidden)
        guard.setattr(service.accounting, "advance", forbidden)
        with _repeatable_read_transaction(case.engine) as connection:
            raw = service.capture_in_transaction(
                connection,
                account_id=case.h.account,
                refs=decision.evidence.inputs,
                owner_command_ref=None,
                budget=RuntimeReadBudget(),
            )
        with case.store.write_transaction() as connection:
            service.recheck_descriptor_in_transaction(connection, resolved, require_current=True)
    result = service.resolve(
        raw,
        assignment=resolved.plan.daily.assignment,
        previous=None,
        refs=decision.evidence.inputs,
        owner_command_ref=None,
        fence_receipt=resolved.plan.daily.raw.receipt,
        control=resolved.plan.daily.control,
    )
    assert result.snapshot == decision.snapshot


def test_changed_immutable_original_lease_is_rejected_at_final_recheck(source):
    import sqlalchemy as sa

    from packages.persistence.schema import phase2_account_leases

    case, service, _previous, _request, prepared, resolved, _ = source
    with _write_transaction(case.engine) as connection:
        connection.execute(
            sa.update(phase2_account_leases)
            .where(
                phase2_account_leases.c.lease_sha256
                == prepared.descriptor.captured_fence.lease_sha256
            )
            .values(canonical_payload="tampered")
        )
    with pytest.raises(ValueError), case.store.write_transaction() as connection:
        service.recheck_descriptor_in_transaction(connection, resolved, require_current=True)


def test_source_capture_charges_real_tables_and_auxiliary_journals(source):
    from packages.persistence.daily_runtime_risk import RuntimeReadBudget
    from packages.persistence.database import _repeatable_read_transaction

    case, service, _previous, _request, prepared, resolved, _ = source
    decision = actual_decision(source)
    budget = RuntimeReadBudget()
    budget.captured.extend(resolved.plan.daily.raw.tables)
    with _repeatable_read_transaction(case.engine) as connection:
        raw = service.capture_in_transaction(
            connection,
            account_id=case.h.account,
            refs=decision.evidence.inputs,
            owner_command_ref=None,
            budget=budget,
        )
    assert {item.table.name for item in raw.tables} == {
        "personal_continuous_account_commits",
        "personal_continuous_account_heads",
        "phase2_account_leases",
    }
    assert budget.rows > sum(len(item.rows) for item in raw.tables)
    assert budget.payload_bytes > prepared.reference.object_ref.byte_count
    limited = RuntimeReadBudget(metadata_bytes=2 * 1024 * 1024)
    with pytest.raises(ValueError), _repeatable_read_transaction(case.engine) as connection:
        service.capture_in_transaction(
            connection,
            account_id=case.h.account,
            refs=decision.evidence.inputs,
            owner_command_ref=None,
            budget=limited,
        )


def test_historical_source_replay_keeps_original_times_after_control_and_clock_changes(source):
    from packages.domain.operational_control import (
        OperationalControlCommandKind,
        OperationalControlState,
    )
    from packages.persistence.database import _repeatable_read_transaction

    case, service, previous, _request, descriptor, _resolved, clock = source
    prepared = prepare_admission(source)
    view = case.h.store.inspect_prepared_admission(prepared)
    with case.store.write_transaction() as connection:
        case.h.store.admit_prepared_in_transaction(connection, prepared, fence=case.h.lease.fence)
    reference = service.retain_admission_sources(view, snapshot=prepared.snapshot.raw.producer)
    case.h.controls.apply(
        case.h.command(
            OperationalControlCommandKind.PAUSE, "later-pause", OperationalControlState.PAUSED
        )
    )
    clock.advance(30)
    plan = service.prepare_admission_source_read(
        reference, record_sha256=view.record_sha256, previous=previous
    )
    with _repeatable_read_transaction(case.engine) as connection:
        raw = service.capture_admission_sources_in_transaction(connection, plan)
    historical = service.resolve_admission_sources(raw, admission=view, previous=previous)
    with case.store.write_transaction() as connection:
        service.recheck_admission_sources_in_transaction(connection, historical)
    assert historical.state.plan.descriptor == descriptor.descriptor


def test_actual_paired_cash_model_is_used_without_relabeling_provider_semantics(
    tmp_path, monkeypatch
):
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
    finally:
        paired.close()


def fresh_reader(case, original, *, producer_map=None):
    operating = SqlRuntimeOperatingEvidence(
        case.engine,
        journal=SqlDurableJournal(
            case.engine, codec=codec, record_types={CLOCK_SCHEMA: RuntimeClockObservation}
        ),
        artifacts=case.artifacts,
        codec=codec,
        clock_sampler=original.operating.clock_sampler,
    )
    return SqlContinuousRuntimeSources(
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
        accounting=original.accounting,
        strategy=original.strategy,
        venue_model=original.venue_model,
        venue_reference=original.venue_reference,
        producer_map=original.producer_map if producer_map is None else producer_map,
        benchmark_instrument_id=original.benchmark_instrument_id,
        current_fence=lambda: case.h.lease.fence,
    )


def test_fresh_reader_restores_published_original_without_active_descriptor_cache(source):
    case, service, previous, request, descriptor, _resolved, _clock = source
    transition = case.owner.prepare_frontier(
        command_id="fresh-reader-close", checkpoint=previous.checkpoint, frontier=request
    )
    admission = prepare_admission(source)
    receipt = case.publish(transition, previous, descriptor.descriptor.market_source, (admission,))
    restarted = fresh_reader(case, service)
    case.h.store.producers = restarted
    case.reader = restarted
    case.owner.runtime_evidence = restarted
    case.store = case.new_store()
    restarted.bind_stores(accounts=case.store, daily=case.h.store)
    restored = case.store.restore(case.scope)
    assert restored.receipt == receipt
    assert restored.checkpoint == transition.checkpoint
    assert not restarted._active  # Historical replay never registers current evidence.


@pytest.mark.parametrize("role", ["account", "clock", "reconciliation"])
def test_arbitrary_fixed_role_pin_is_rejected_by_concrete_constructor(source, role):
    case, service, *_ = source
    wrong = replace(
        service.producer_map,
        producers=tuple(
            replace(item, producer=replace(item.producer, sha256="f" * 64))
            if item.role == role
            else item
            for item in service.producer_map.producers
        ),
    )
    with pytest.raises(ValueError, match="FIXED_PRODUCER_PROFILE_DIFFERS"):
        fresh_reader(case, service, producer_map=wrong)


@pytest.mark.parametrize(
    "field,value",
    [("producer", None), ("provider_id", "etrade"), ("source_environment", "sandbox")],
)
def test_retained_market_must_match_advertised_pin_provider_and_environment(source, field, value):
    case, service, previous, request, descriptor, *_ = source
    actual = next(item for item in service.producer_map.producers if item.role == "daily_inputs")
    replacement = replace(
        actual,
        **{field: replace(actual.producer, sha256="f" * 64) if field == "producer" else value},
    )
    wrong = replace(
        service.producer_map,
        producers=tuple(
            replacement if item.role == "daily_inputs" else item
            for item in service.producer_map.producers
        ),
    )
    restarted = fresh_reader(case, service, producer_map=wrong)
    with pytest.raises(ValueError, match="MARKET_PRODUCER_SCOPE_DIFFERS"):
        restarted._normalize(descriptor.descriptor.market_source, request, previous, "frontier")


def test_nested_original_descriptor_mutation_rejects_final_sql_recheck(source):
    case, service, _previous, _request, prepared, resolved, _ = source
    pin = prepared.descriptor.producer_map.producers[0].producer
    original = pin.sha256
    object.__setattr__(pin, "sha256", "f" * 64)
    try:
        with (
            pytest.raises(ValueError, match="DESCRIPTOR_MUTATED"),
            case.store.write_transaction() as connection,
        ):
            service.recheck_descriptor_in_transaction(connection, resolved, require_current=True)
    finally:
        object.__setattr__(pin, "sha256", original)


def test_original_append_retry_after_later_descriptor_returns_original_receipt(source):
    case, service, previous, request, first, resolved, _ = source
    later = service.prepare_descriptor(
        descriptor_id="later-source-descriptor",
        scope=case.scope,
        request=request,
        market_source=first.descriptor.market_source,
        previous=previous,
        fence=case.h.lease.fence,
        clock_reference=resolved.plan.operating.clock_reference,
        request_kind="frontier",
        accounts=case.store,
        daily=case.h.store,
    )
    with case.store.write_transaction() as connection:
        service.append_descriptor_in_transaction(connection, later, fence=case.h.lease.fence)
        actual = service.append_descriptor_in_transaction(
            connection, first, fence=case.h.lease.fence
        )
    assert actual == first.reference
    assert (
        service.journal.read_receipt(first.append.key, first.descriptor.descriptor_id)
        == first.append.receipt
    )
    assert service.journal.read_head(first.append.key) == later.append.receipt.committed_head


@pytest.mark.parametrize("matching_clock", [True, False])
def test_actual_quote_prefix_preserves_side_deadlines_and_does_not_reapply_itself(
    tmp_path, monkeypatch, matching_clock
):
    from types import SimpleNamespace

    import tests.integration.test_continuous_quote_composition as quote_fixture
    from packages.application.continuous_quote_frontier import project_continuous_quote_frontier
    from packages.domain.continuous_quote_contracts import CONTINUOUS_QUOTE_CLOSURE_SCHEMA
    from packages.domain.forward_capture_contracts import CaptureClockSample
    from tests.unit.test_personal_forward_capture import Clock as CaptureClock

    def new_case(path, **kwargs):
        case = Case(path, **kwargs)
        cp = case.first.checkpoint
        case.test_venue = model(
            initial_cash_flow=cp.state.cash_flows[0],
            instruments=cp.inputs.spec.instruments,
            execution_policy=replace(
                cp.inputs.spec.execution_policy, model_id="stateful-venue-facts-v1"
            ),
        )
        install_producers(case, case.test_venue)
        return case

    monkeypatch.setattr(quote_fixture, "Case", new_case)
    if matching_clock:
        monkeypatch.setattr(
            quote_fixture,
            "Clock",
            lambda at: CaptureClock(
                at,
                samples=tuple(
                    CaptureClockSample(
                        at + timedelta(milliseconds=n),
                        60_700_000_000 + n * 1_000_000,
                        "explicit-test-epoch",
                    )
                    for n in (0, 100, 200)
                ),
            ),
        )
    fixture = quote_fixture.case.__wrapped__(tmp_path)
    case, previous, closure = next(fixture)
    try:
        clock, sampler, sample = healthy_sampler(case.scope, at=closure.admitted_at)
        if matching_clock:
            closure = replace(closure, admitted_monotonic_ns=clock.mono)
        operating = SqlRuntimeOperatingEvidence(
            case.engine,
            journal=SqlDurableJournal(
                case.engine, codec=codec, record_types={CLOCK_SCHEMA: RuntimeClockObservation}
            ),
            artifacts=case.artifacts,
            codec=codec,
            clock_sampler=sampler,
        )
        append = operating.prepare_clock_append(
            sample, expected_head=empty_head(operating.clock_key())
        )
        with _write_transaction(case.engine) as connection:
            clock_ref = operating.append_clock_in_transaction(connection, append)
        venue = case.test_venue
        holder = SimpleNamespace(
            operating=operating,
            accounting=case.owner.accounting,
            strategy=case.owner.strategy,
            venue_model=venue,
            venue_reference=VenueSourceReference(
                venue.producer,
                venue.semantic_sha256,
                case.artifacts.put(codec.encode_record(venue)),
            ),
            producer_map=case.h.producer_map,
            benchmark_instrument_id=case.inputs.spec.instruments[0][0],
        )
        service = fresh_reader(case, holder)
        case.h.store.producers = service
        case.reader = service
        case.owner.runtime_evidence = service
        case.store = case.new_store()
        service.bind_stores(accounts=case.store, daily=case.h.store)
        previous = case.store.restore(case.scope)
        market = case.forward.resolve(closure)
        frontier = project_continuous_quote_frontier(
            checkpoint=previous.checkpoint, closure=closure, source_state=market.state
        )
        source_ref = case.put(CONTINUOUS_QUOTE_CLOSURE_SCHEMA, closure)
        transition = case.owner.prepare_frontier(
            command_id="actual-quote-prefix", checkpoint=previous.checkpoint, frontier=frontier
        )
        case.publish(transition, previous, source_ref)
        current = case.store.restore(case.scope)
        descriptor = service.prepare_descriptor(
            descriptor_id="activation-source-only",
            scope=case.scope,
            request=frontier,
            market_source=source_ref,
            previous=current,
            fence=case.h.lease.fence,
            clock_reference=clock_ref,
            request_kind="activation_dependencies",
            accounts=case.store,
            daily=case.h.store,
        )
        with case.store.write_transaction() as connection:
            service.append_descriptor_in_transaction(
                connection, descriptor, fence=case.h.lease.fence
            )
        resolved = service.resolve_prepared_descriptor(descriptor)
        # Inspect role projection only; the fixture batch does not claim an
        # activation decision or dispatch. Actual source/C/B owners were used.
        conditions = service.evidence_port(resolved).evaluator.evaluate(
            snapshot=current.checkpoint.current.snapshot,
            batch=case.h.batch,
            phase="activation",
            evaluated_at=closure.admitted_at,
            request_rows=current.checkpoint.request_rows,
        )
        by_role = {item.role: item for item in conditions}
        quote = closure.publications[0].record.observations[0].payload
        receipt = closure.publications[0].record.receipt
        assert "daily_inputs" not in by_role
        assert by_role["quotes"].source_at == min(quote.bid_at, quote.ask_at)
        assert by_role["quotes"].received_at == receipt.received_at
        assert by_role["quotes"].valid_until == min(
            quote.bid_at + timedelta(seconds=5),
            quote.ask_at + timedelta(seconds=5),
            receipt.received_at + timedelta(seconds=1),
            descriptor.descriptor.captured_fence.valid_until,
        )
        assert by_role["quotes"].status == ("available" if matching_clock else "unavailable")
        assert by_role["quotes"].reasons == (
            () if matching_clock else ("ORIGINAL_QUOTE_CLOCK_TUPLE_DIFFERS",)
        )
        assert current.checkpoint == transition.checkpoint
    finally:
        fixture.close()
