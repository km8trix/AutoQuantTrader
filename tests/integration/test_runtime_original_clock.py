"""Original clock journals remain immutable evidence without renewing authority."""

from dataclasses import replace

import pytest
import sqlalchemy as sa

from packages.persistence.daily_runtime_risk import RuntimeReadBudget
from packages.persistence.durable_journal_schema import journal_entries
from tests.integration.test_continuous_runtime_sources import source as source


def original(source):
    _case, service, _previous, _request, prepared, *_ = source
    return service.read_original_clock(prepared.operating.clock_reference)


def test_original_clock_preserves_expired_observation_without_current_sampler(source, monkeypatch):
    case, service, *_rest, clock = source
    value = original(source)
    instant = value.observation.observed_at_utc
    clock.advance(3600)

    def forbidden(*args, **kwargs):
        raise AssertionError("historical clock read cannot sample or renew")

    monkeypatch.setattr(type(service.operating.clock_sampler), "require_current", forbidden)
    again = service.read_original_clock(value.reference)
    assert again.observation == value.observation
    assert again.observation.observed_at_utc == instant
    with case.store.write_transaction() as connection:
        service.recheck_original_clock_in_transaction(connection, again)


@pytest.mark.parametrize("mutation", ["clone", "nested"])
def test_original_clock_owner_rejects_clone_or_nested_mutation(source, mutation):
    value = original(source)
    if mutation == "clone":
        value = replace(value)
    else:
        object.__setattr__(value.observation, "sequence", value.observation.sequence + 1)
    with pytest.raises(ValueError):
        source[1].require_original_clock(value)


def test_original_clock_final_sql_checks_original_journal_without_hash_or_codec(
    source, monkeypatch
):
    case, service, *_ = source
    value = original(source)

    def forbidden(*args, **kwargs):
        raise AssertionError("clock readback must remain compact SQL")

    monkeypatch.setattr(service.codec, "encode_record", forbidden)
    monkeypatch.setattr(service.codec, "decode_record", forbidden)
    monkeypatch.setattr(service.artifacts, "read", forbidden)
    with case.store.write_transaction() as connection:
        service.recheck_original_clock_in_transaction(connection, value)
    with case.engine.begin() as connection:
        connection.execute(
            sa.update(journal_entries)
            .where(journal_entries.c.record_id == value.reference.record.semantic_sha256)
            .values(payload=b"{}")
        )
    with pytest.raises(ValueError), case.store.write_transaction() as connection:
        service.recheck_original_clock_in_transaction(connection, value)


def test_original_clock_capture_obeys_shared_sql_budget(source):
    value = original(source)
    with pytest.raises(ValueError):
        source[1].read_original_clock(
            value.reference, budget=RuntimeReadBudget(payload_bytes=32 * 1024 * 1024)
        )


def test_historical_descriptor_outer_object_budget_rejects_before_any_read(source, monkeypatch):
    _case, service, _previous, _request, prepared, *_ = source
    reads = []
    monkeypatch.setattr(service.artifacts, "read", lambda *args, **kwargs: reads.append(args))

    def reject(refs):
        assert refs == (prepared.reference.object_ref,)
        raise ValueError("outer graph exhausted")

    with pytest.raises(ValueError, match="outer graph exhausted"):
        service.prepare_historical_descriptor(prepared.reference, admit_objects=reject)
    assert not reads


def test_historical_activation_reader_rejects_original_decision_descriptor(source):
    with pytest.raises(ValueError, match="HISTORICAL_ACTIVATION_DESCRIPTOR_REQUIRED"):
        source[1].prepare_historical_descriptor(source[4].reference)
