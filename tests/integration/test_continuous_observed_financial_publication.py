"""Fixed actual C/B/A source graph and independent synthetic venue observations.

The initial assignment is the existing labelled fixture. Observation provenance,
sole accounting, source ownership and all coupled publication rows are actual.
"""

from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.stateful_venue_contracts import VenueCommand
from packages.domain.venue_reconciliation_contracts import VenueCaptureRequest
from packages.persistence.applied_reconciliation_schema import applied_reconciliation_commits
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_observed_hold_sources import SqlContinuousObservedHoldSources
from packages.persistence.continuous_observed_publication import SqlContinuousObservedPublication
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.schema import phase5_operational_control_transitions
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
from tests.integration.test_continuous_reconciliation_publication import PublicationCase
from tests.integration.test_continuous_runtime_sources import install_producers
from tests.integration.test_runtime_owner_dependencies import attach
from tests.integration.test_venue_reconciliation_capture import Clock


def bind_observed(pair, runtime):
    case = pair.base
    reader = SqlContinuousObservedHoldSources(
        case.engine,
        accounts=pair.account,
        preparer=case.owner,
        venue_sources=pair.sources,
        daily=case.h.store,
        artifacts=case.artifacts,
        codec=codec,
    )
    runtime.bind_observed_hold_sources(reader)
    return SqlContinuousObservedPublication(account=pair.account)


@pytest.fixture
def graph(tmp_path):
    pair = PublicationCase(tmp_path)
    case = pair.base
    # Match the concrete factory's single canonical accounting instance. The
    # independent venue retains its separate instance of the same sole reducer.
    pair.accounting = case.owner.accounting
    install_producers(case, pair.model)
    _owners, runtime, *_ = attach(pair)
    wrapper = bind_observed(pair, runtime)
    try:
        yield pair, wrapper
    finally:
        pair.close()


def captured(pair, *, name="observed-financial"):
    case = pair.base
    independent = pair.venue.read()
    at = max(case.h.clock.instant, independent.state.as_of) + timedelta(seconds=1)
    source = SqlVenueReconciliationCapture(
        case.engine, artifacts=case.artifacts, codec=codec, clock=Clock(at)
    ).capture(
        VenueCaptureRequest(
            name,
            pair.binding,
            case.inputs.spec.initialized_at,
            independent.state.as_of,
            independent.head,
        ),
        venue=pair.venue,
    )
    case.h.clock.instant = at + timedelta(milliseconds=10)
    previous = pair.account.restore(case.scope)
    current = case.h.resolved()
    prior = pair.publisher.restore(pair.scope, account_scope=case.scope)
    return dict(
        command_id=name,
        previous=previous,
        current=current,
        venue=pair.sources.resolve(source),
        prior=prior,
    )


def counts(pair):
    with pair.base.engine.connect() as connection:
        return tuple(
            connection.scalar(sa.select(sa.func.count()).select_from(table))
            for table in (
                continuous_account_commits,
                applied_reconciliation_commits,
                journal_entries,
                *DAILY_RUNTIME_TABLES,
            )
        )


def contribute(pair):
    at = pair.base.h.clock.instant + timedelta(milliseconds=10)
    flow = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=Decimal(500),
        effective_at=at,
        recorded_at=at,
        external_reference="independent-extra-cash",
    )
    pair.venue.execute(VenueCommand("independent-extra-cash", at, flow))
    return flow


def test_fixed_wrapper_applies_actual_external_cash_and_restores_original_pair(graph):
    pair, wrapper = graph
    flow = contribute(pair)
    inputs = captured(pair)
    prepared = wrapper.prepare(**inputs)
    assert prepared.source.current is inputs["current"]
    assert prepared.source.previous is inputs["previous"]
    assert prepared.source.venue is inputs["venue"]
    assert prepared.source.inputs.source.applied_at == inputs["current"].raw.receipt.validated_at
    assert prepared.source.inputs.resulting.current.snapshot.trade_date_cash == Decimal(10500)
    receipt = wrapper.publish(prepared)
    restored = pair.publisher.restore(pair.scope, account_scope=pair.base.scope)
    assert restored.continuous.receipt == receipt.continuous
    assert restored.reconciliation.receipt == receipt.reconciliation
    assert restored.continuous.checkpoint.state == prepared.source.inputs.resulting.state
    assert flow in restored.continuous.checkpoint.state.cash_flows
    before = counts(pair)
    assert pair.publisher.retry(restored, fence=pair.base.h.lease.fence) == receipt
    assert counts(pair) == before
    overlap = wrapper.prepare(**captured(pair, name="observed-overlap"))
    assert overlap.holds.result.group is None
    assert overlap.holds.result.before == overlap.holds.result.after
    wrapper.publish(overlap)
    assert pair.account.restore(pair.base.scope).checkpoint.state.cash_flows.count(flow) == 1


@pytest.mark.parametrize("which", ["previous", "current", "venue", "prepared", "source", "holds"])
def test_fixed_wrapper_requires_original_owned_tokens(graph, which):
    pair, wrapper = graph
    inputs = captured(pair)
    if which in inputs:
        inputs[which] = replace(inputs[which])
        with pytest.raises(ValueError):
            wrapper.prepare(**inputs)
    else:
        prepared = wrapper.prepare(**inputs)
        if which == "prepared":
            prepared = replace(prepared)
        else:
            object.__setattr__(prepared, which, replace(getattr(prepared, which)))
        with pytest.raises(ValueError):
            wrapper.publish(prepared)


@pytest.mark.parametrize("fault", ["applied", "control", "source", "deadline"])
def test_late_applied_source_control_or_deadline_change_rolls_back_all_rows(
    graph, monkeypatch, fault
):
    pair, wrapper = graph
    contribute(pair)
    prepared = wrapper.prepare(**captured(pair))
    before = counts(pair)
    original = pair.publisher.applied.commit_in_transaction

    def late(connection, **kwargs):
        receipt = original(connection, **kwargs)
        if fault == "applied":
            connection.execute(
                sa.update(applied_reconciliation_commits).values(canonical_payload=b"changed")
            )
        elif fault == "control":
            connection.execute(
                sa.update(phase5_operational_control_transitions).values(
                    canonical_payload="changed"
                )
            )
        elif fault == "source":
            key = prepared.source.venue.reads[0].snapshot.key.semantic_sha256
            connection.execute(
                sa.update(journal_entries)
                .where(journal_entries.c.key_sha256 == key)
                .values(payload=b"changed")
            )
        else:
            pair.base.h.clock.instant = prepared.holds.valid_until
        return receipt

    monkeypatch.setattr(pair.publisher.applied, "commit_in_transaction", late)
    with pytest.raises(ValueError):
        wrapper.publish(prepared)
    assert counts(pair) == before
    if fault != "deadline":
        assert (
            pair.account.restore(pair.base.scope).checkpoint.state
            == prepared.source.inputs.previous.state
        )


def test_fixed_wrapper_has_no_codec_object_or_reducer_work_inside_publication_sql(
    graph, monkeypatch
):
    pair, wrapper = graph
    prepared = wrapper.prepare(**captured(pair))
    original = pair.account.write_transaction

    def forbidden(*args, **kwargs):
        raise AssertionError("heavy work inside actual observed publication SQL")

    @contextmanager
    def guarded():
        with original() as connection, monkeypatch.context() as patch:
            for obj, method in (
                (codec, "encode_record"),
                (codec, "decode_record"),
                (pair.base.artifacts, "read"),
                (pair.base.artifacts, "put"),
                (pair.base.owner, "prepare_frontier"),
                (wrapper.runtime.accounting, "advance"),
            ):
                patch.setattr(obj, method, forbidden)
            yield connection

    monkeypatch.setattr(pair.account, "write_transaction", guarded)
    wrapper.publish(prepared)


def test_actual_in_flight_partial_fill_preserves_original_attempt_sources(tmp_path, monkeypatch):
    from packages.domain.stateful_venue_contracts import VenueAccept
    from packages.persistence.continuous_venue_registration_capture import (
        SqlContinuousVenueRegistrationCapture,
    )
    from packages.persistence.daily_runtime_risk_schema import daily_runtime_hold_events
    from tests.integration import test_continuous_runtime_attempt_sources as attempt_fixture
    from tests.integration.test_continuous_attempt_outcome_sources import outcome_owner
    from tests.integration.test_continuous_simulation_delivery import activated_delivery
    from tests.unit.test_stateful_venue import quote

    restart = PublicationCase.restart

    def canonical_owner(pair):
        pair.accounting = pair.base.owner.accounting
        restart(pair)

    monkeypatch.setattr(PublicationCase, "restart", canonical_owner)
    fixture = attempt_fixture.attempt_case.__wrapped__(tmp_path, monkeypatch)
    try:
        actual = next(fixture)
        case, source, _descriptor, _publisher, batch, delivery, venue = activated_delivery(actual)
        pair = case.paired_fixture
        wrapper = bind_observed(pair, delivery.runtime)
        helper, capture_clock = outcome_owner(case, delivery, venue)
        mapper = SqlContinuousVenueRegistrationCapture(outcomes=helper)
        attempt_id = source.envelopes[0].event.attempt_id
        delivery.deliver(batch, source=source, attempt_id=attempt_id)
        order_id = source.closure.preparations[0].request.submission.order_id
        case.h.clock.instant += timedelta(milliseconds=20)
        venue.execute(
            VenueCommand(
                "known-working-before-financial-fill", case.h.clock.instant, VenueAccept(order_id)
            )
        )
        case.h.clock.instant += timedelta(milliseconds=20)
        modeled = quote(case.h.clock.instant, name="independent-modeled-partial", budget="1")
        modeled = replace(
            modeled,
            observation=replace(
                modeled.observation,
                payload=replace(
                    modeled.observation.payload,
                    instrument_id=source.closure.preparations[
                        0
                    ].request.submission.intent.instrument_id,
                ),
            ),
        )
        acknowledgment = venue.execute(
            VenueCommand("independent-model-fill", case.h.clock.instant, modeled)
        )
        assert acknowledgment.acknowledgment.disposition == "applied"
        capture_clock.at = case.h.clock.instant
        previous, current = case.store.restore(case.scope), case.h.resolved()
        captured_source = mapper.capture(
            capture_id="actual-mapped-partial", previous=previous, current=current
        )
        case.h.clock.instant = capture_clock.at + timedelta(milliseconds=1)
        prepared = wrapper.prepare(
            command_id="actual-fixed-partial",
            previous=previous,
            current=case.h.resolved(),
            venue=captured_source,
            prior=pair.restore(),
        )
        before = prepared.holds.result.before.bindings[0].commitment
        after = prepared.holds.result.after.bindings[0].commitment
        assert before.remaining_quantity - after.remaining_quantity == 1
        assert after.reserved_cash < before.reserved_cash
        assert all(item.state.value == "in_flight" for item in current.attempts)
        original = pair.publisher.applied.commit_in_transaction
        before_counts = counts(pair)
        assert source.closure.descriptor_receipt is not None
        for fault in ("hold", "original_attempt", "original_activation"):

            def late(connection, _fault=fault, **kwargs):
                receipt = original(connection, **kwargs)
                if _fault == "hold":
                    statement = (
                        sa.update(daily_runtime_hold_events)
                        .where(daily_runtime_hold_events.c.revision > 1)
                        .values(payload=b"late-hold")
                    )
                elif _fault == "original_attempt":
                    statement = (
                        sa.update(journal_entries)
                        .where(
                            journal_entries.c.key_sha256
                            == source.closure.dispatch_keys[0].semantic_sha256
                        )
                        .values(payload=b"late-original-dispatch")
                    )
                else:
                    statement = (
                        sa.update(journal_entries)
                        .where(
                            journal_entries.c.key_sha256
                            == source.closure.descriptor_receipt.committed_head.key_sha256
                        )
                        .values(payload=b"late-original-activation-descriptor")
                    )
                assert connection.execute(statement).rowcount > 0
                return receipt

            with monkeypatch.context() as patch:
                patch.setattr(pair.publisher.applied, "commit_in_transaction", late)
                with pytest.raises(ValueError):
                    wrapper.publish(prepared)
            assert counts(pair) == before_counts
        receipt = wrapper.publish(prepared)
        restored = case.store.restore(case.scope)
        assert restored.receipt == receipt.continuous
        assert case.h.resolved().obligations == prepared.holds.result.after
        assert restored.checkpoint.state == prepared.source.inputs.resulting.state
    finally:
        fixture.close()
