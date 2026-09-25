"""B's shared runtime producer retains the actual independent venue source owner."""

from dataclasses import replace

import pytest

from packages.persistence.continuous_runtime_sources import ContinuousRuntimeSourceError
from packages.persistence.daily_runtime_risk import RuntimeReadBudget
from tests.integration.test_continuous_observed_hold_sources import resolver, retain
from tests.integration.test_continuous_runtime_attempt_sources import attempt_case as attempt_case


def test_same_producer_observed_source_capture_and_exact_postpublication_recheck(attempt_case):
    case, producer, _attempt_reader, *_ = attempt_case
    reader = resolver(case.paired_fixture)
    producer.bind_observed_hold_sources(reader)
    producer.bind_observed_hold_sources(reader)
    token = retain(case.paired_fixture, reader)
    plan = producer.prepare_observed_hold_source_read((token.reference,))
    with case.store.write_transaction() as connection:
        raw = producer.capture_observed_hold_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )
    resolved = producer.resolve_observed_hold_sources(raw, admissions=())
    reader.require_resolved(resolved)
    assert resolved.inputs == (token.inputs,)
    with case.store.write_transaction() as connection:
        producer.recheck_observed_hold_sources_in_transaction(connection, resolved)
    prepared = case.store.prepare(
        token.transition,
        scope=case.scope,
        previous=token.previous,
        source_evidence=token.inputs.source.venue_capture,
    )
    with case.store.write_transaction() as connection:
        receipt = case.store.commit_in_transaction(
            connection, prepared=prepared, fence=case.h.lease.fence
        )
        producer.recheck_observed_hold_sources_after_publication_in_transaction(
            connection, resolved, prepared_account=prepared, account_receipt=receipt
        )
        with pytest.raises(ValueError):
            producer.recheck_observed_hold_sources_after_publication_in_transaction(
                connection,
                resolved,
                prepared_account=prepared,
                account_receipt=replace(receipt),
            )


@pytest.mark.parametrize("mutation", ["unbound", "reader", "codec", "preparer", "venue"])
def test_same_producer_observed_reader_rejects_missing_or_changed_exact_owner(
    attempt_case, mutation
):
    case, producer, _attempt_reader, *_ = attempt_case
    reader = resolver(case.paired_fixture)
    if mutation != "unbound":
        producer.bind_observed_hold_sources(reader)
        if mutation == "reader":
            producer.observed_hold_sources = object()
        elif mutation == "venue":
            reader.venue_sources = object()
        else:
            setattr(reader, mutation, object())
    with pytest.raises(ContinuousRuntimeSourceError):
        producer.prepare_observed_hold_source_read(())


def test_same_producer_observed_reader_rejects_changed_original_model_pins(attempt_case):
    case, producer, _attempt_reader, *_ = attempt_case
    reader = resolver(case.paired_fixture)
    producer.bind_observed_hold_sources(reader)
    model = reader.venue_sources.model
    old = model.account_id
    try:
        object.__setattr__(model, "account_id", "replaced-venue-account")
        with pytest.raises(ContinuousRuntimeSourceError, match="PINS_CHANGED"):
            producer.prepare_observed_hold_source_read(())
    finally:
        object.__setattr__(model, "account_id", old)
