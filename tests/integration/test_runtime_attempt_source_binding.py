"""The shared B producer retains the actual concrete attempt source owner."""

import pytest

from packages.persistence.continuous_runtime_sources import ContinuousRuntimeSourceError
from packages.persistence.daily_runtime_risk import RuntimeReadBudget
from tests.integration.test_continuous_runtime_attempt_sources import (
    attempt_case as attempt_case,
)
from tests.integration.test_continuous_runtime_attempt_sources import pending


def test_same_producer_delegates_actual_owned_attempt_capture_and_recheck(attempt_case):
    case, producer, reader, _previous, _current, admission = attempt_case
    producer.bind_attempt_sources(reader)
    prepared = pending(attempt_case)
    plan = producer.prepare_attempt_source_read((prepared.reference,))
    with case.store.write_transaction() as connection:
        snapshot = producer.capture_attempt_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )
    resolved = producer.resolve_attempt_sources(snapshot, admissions=(admission,))
    reader.require_resolved(resolved)
    assert resolved.sources == (prepared.source,)
    with case.store.write_transaction() as connection:
        producer.recheck_attempt_sources_in_transaction(connection, resolved)


@pytest.mark.parametrize("mutation", ["unbound", "reader", "codec", "preparer"])
def test_same_producer_rejects_missing_or_mutated_actual_owner(attempt_case, mutation):
    _case, producer, reader, *_ = attempt_case
    if mutation == "unbound":
        producer.attempt_sources = None
    else:
        producer.bind_attempt_sources(reader)
        if mutation == "reader":
            producer.attempt_sources = object()
        else:
            setattr(reader, mutation, object())
    with pytest.raises(ContinuousRuntimeSourceError):
        producer.prepare_attempt_source_read(())
