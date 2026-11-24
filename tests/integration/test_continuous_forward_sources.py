"""Disposable SQL/raw-object fixtures, explicitly unable to qualify provider access."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest
import sqlalchemy as sa

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.personal_forward_capture import replay_capture
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
from packages.domain.forward_contracts import ForwardDataState
from packages.persistence.continuous_forward_sources import (
    ContinuousForwardSourceError,
    SqlContinuousForwardSources,
)
from packages.persistence.database import _repeatable_read_transaction, create_database_engine
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.schema import metadata
from tests.integration.test_personal_forward_capture_journal import capture, journal
from tests.unit.test_personal_forward_capture import AT, Clock, Transport, daily_body, request


@pytest.fixture
def case(tmp_path):
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/capture.sqlite")
    metadata.create_all(engine, tables=JOURNAL_TABLES)
    artifacts = LocalResearchArtifactStore(tmp_path / "objects")
    req = request("daily")
    state = ForwardDataState((req.source,), "recorded")
    at = AT.replace(hour=21, minute=0)
    publication = capture(
        req, state, journal(engine), artifacts, clock=Clock(at), transport=Transport(daily_body())
    )
    closure = ContinuousForwardClosure(
        account_id=req.journal_key.account_scope,
        closure_id="session-close",
        initial_state=state,
        publications=(publication,),
        observation_ids=(publication.record.observations[0].observation_id,),
        admitted_at=at + timedelta(seconds=1),
        evidence_class="synthetic_fixture",
    )
    store = SqlContinuousForwardSources(
        engine, artifacts=artifacts, codec=personal_codec, evidence_class="synthetic_fixture"
    )
    yield engine, artifacts, closure, store
    engine.dispose()


def test_original_raw_receipts_replay_after_restart_and_later_capture(case):
    engine, artifacts, closure, store = case
    resolved = store.resolve(closure)
    assert resolved.state == replay_capture(
        closure.publications[0].record, closure.initial_state, artifacts=artifacts
    )
    first = closure.publications[0]
    second = capture(
        replace(first.record.request, capture_id="later"),
        resolved.state,
        journal(engine),
        artifacts,
        clock=Clock(closure.admitted_at + timedelta(seconds=1)),
        transport=Transport(daily_body(close=100.5)),
        head=first.journal_receipt.committed_head,
    )
    with _repeatable_read_transaction(engine) as connection:
        store.recheck_in_transaction(connection, resolved)
    restarted = SqlContinuousForwardSources(
        engine, artifacts=artifacts, codec=personal_codec, evidence_class="synthetic_fixture"
    ).resolve(closure)
    assert restarted.state == resolved.state
    assert second.record.receipt.validated_at > closure.admitted_at
    assert restarted.state.observations[0].known_at == first.record.receipt.validated_at


def test_fixture_class_cannot_be_used_as_actual_provider_evidence(case):
    engine, artifacts, closure, _ = case
    actual = SqlContinuousForwardSources(
        engine, artifacts=artifacts, codec=personal_codec, evidence_class="provider_https_read"
    )
    with pytest.raises(ContinuousForwardSourceError, match="PROMOTED"):
        actual.resolve(closure)


def test_original_capture_byte_tampering_blocks_final_commit(case):
    engine, _, closure, store = case
    resolved = store.resolve(closure)
    with engine.begin() as connection:
        connection.execute(
            sa.update(journal_entries).where(journal_entries.c.sequence == 1).values(payload=b"{}")
        )
    with (
        _repeatable_read_transaction(engine) as connection,
        pytest.raises(ContinuousForwardSourceError),
    ):
        store.recheck_in_transaction(connection, resolved)
    with pytest.raises(ContinuousForwardSourceError):
        store.resolve(closure)


def test_copy_and_wrong_owner_cannot_supply_source_resolution(case):
    engine, artifacts, closure, store = case
    resolved = store.resolve(closure)
    other = SqlContinuousForwardSources(
        engine, artifacts=artifacts, codec=personal_codec, evidence_class="synthetic_fixture"
    )
    with _repeatable_read_transaction(engine) as connection:
        with pytest.raises(ContinuousForwardSourceError, match="OWNED"):
            store.recheck_in_transaction(connection, replace(resolved))
        with pytest.raises(ContinuousForwardSourceError, match="OWNED"):
            other.recheck_in_transaction(connection, resolved)


def test_no_codec_object_read_or_capture_replay_inside_final_transaction(case, monkeypatch):
    engine, artifacts, closure, store = case
    resolved = store.resolve(closure)

    def forbidden(*args, **kwargs):
        raise AssertionError("external replay inside account transaction")

    monkeypatch.setattr(personal_codec, "encode_record", forbidden)
    monkeypatch.setattr(personal_codec, "decode_record", forbidden)
    monkeypatch.setattr(artifacts, "read", forbidden)
    with _repeatable_read_transaction(engine) as connection:
        store.recheck_in_transaction(connection, resolved)


def test_missing_selected_observation_or_broken_state_chain_rejects(case):
    _, _, closure, store = case
    with pytest.raises(ContinuousForwardSourceError):
        store.resolve(replace(closure, observation_ids=("not-retained",)))
    pub = closure.publications[0]
    changed = replace(pub, record=replace(pub.record, before_state_sha256="f" * 64))
    with pytest.raises(ContinuousForwardSourceError):
        store.resolve(replace(closure, publications=(changed,)))


@pytest.mark.parametrize(
    "change", ("closure", "state", "reads", "closure_field", "state_field", "read_field")
)
def test_original_nested_source_graph_and_field_identities_are_checked(case, change):
    _, _, closure, store = case
    resolved = store.resolve(closure)
    if change == "closure":
        object.__setattr__(
            resolved.closure, "admitted_at", closure.admitted_at + timedelta(microseconds=1)
        )
    elif change == "state":
        object.__setattr__(resolved.state.observations[0].payload, "close_price", Decimal("123"))
    elif change == "reads":
        object.__setattr__(
            resolved.reads[0],
            "head",
            replace(resolved.reads[0].head, sequence=resolved.reads[0].head.sequence + 1),
        )
    elif change == "closure_field":
        object.__setattr__(resolved, "closure", replace(resolved.closure))
    elif change == "state_field":
        object.__setattr__(resolved, "state", replace(resolved.state))
    else:
        object.__setattr__(resolved, "reads", tuple(list(resolved.reads)))
    with pytest.raises(ContinuousForwardSourceError, match="ORIGINAL_CAPTURE_SOURCE"):
        store.require_resolved(resolved)


def test_same_stream_latest_head_rows_are_interned_in_complete_sql_graph(case):
    engine, artifacts, closure, store = case
    first = closure.publications[0]
    state = store.resolve(closure).state
    second = capture(
        replace(first.record.request, capture_id="second-proof"),
        state,
        journal(engine),
        artifacts,
        clock=Clock(closure.admitted_at + timedelta(seconds=1)),
        transport=Transport(daily_body(close=100.5)),
        head=first.journal_receipt.committed_head,
    )
    complete = replace(
        closure,
        publications=(first, second),
        admitted_at=closure.admitted_at + timedelta(seconds=2),
    )
    value = store.resolve(complete)
    left, right = (item.snapshot for item in value.reads)
    assert left.stream is right.stream
    assert left.head_anchor is right.head_anchor
    assert left.head_receipt.append is right.head_receipt.append
    assert left.head_receipt.entries[0] is right.head_receipt.entries[0]
    store.require_resolved(value)


@pytest.mark.parametrize(
    "budget", ("MAX_FORWARD_SNAPSHOT_BYTES", "MAX_FORWARD_SNAPSHOT_METADATA_BYTES")
)
def test_complete_snapshot_budgets_precede_any_source_decode(case, monkeypatch, budget):
    import packages.persistence.continuous_forward_sources as source_module

    _, artifacts, closure, store = case
    monkeypatch.setattr(source_module, budget, 1)

    def forbidden(*args, **kwargs):
        pytest.fail("decode or object read before SQL aggregate admission")

    monkeypatch.setattr(personal_codec, "decode_record", forbidden)
    monkeypatch.setattr(artifacts, "read", forbidden)
    with pytest.raises(ContinuousForwardSourceError, match="SQL_SNAPSHOT_LIMIT"):
        store.resolve(closure)


def test_corrupt_large_actual_sql_graph_rejects_before_decode_at_original_cap(case, monkeypatch):
    from packages.domain.durable_journal_contracts import (
        MAX_RECORD_BYTES,
        JournalAppend,
        JournalRecord,
    )
    from packages.domain.forward_capture_contracts import CAPTURE_SCHEMA

    engine, artifacts, closure, store = case
    first = closure.publications[0]
    state = store.resolve(closure).state
    second_key = replace(first.record.request.journal_key, stream_id="separate-source-stream")
    second = capture(
        replace(first.record.request, capture_id="second-stream", journal_key=second_key),
        state,
        journal(engine),
        artifacts,
        clock=Clock(closure.admitted_at + timedelta(seconds=1)),
        transport=Transport(daily_body(close=100.5)),
    )
    complete = replace(
        closure,
        publications=(first, second),
        admitted_at=closure.admitted_at + timedelta(seconds=2),
    )
    for number, publication in enumerate(complete.publications):
        raw = personal_codec.encode_record(publication.record)
        records = tuple(
            JournalRecord(f"large-aux-{number}-{i}", CAPTURE_SCHEMA, raw) for i in range(64)
        )
        owner = journal(engine)
        prepared = owner.prepare_append(
            publication.record.request.journal_key,
            JournalAppend(
                f"aux-{number}", "c" * 64, publication.journal_receipt.committed_head, records
            ),
        )
        with engine.begin() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            owner.append_in_transaction(connection, prepared)
    with engine.begin() as connection:
        connection.execute(
            sa.update(journal_entries)
            .where(journal_entries.c.record_id.like("large-aux-%"))
            .values(payload=b"x" * MAX_RECORD_BYTES)
        )
    calls = 0
    original_capture = store.journal.capture_in_transaction

    def captured(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_capture(*args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("corrupt aggregate must fail before source decoding")

    monkeypatch.setattr(store.journal, "capture_in_transaction", captured)
    monkeypatch.setattr(personal_codec, "decode_record", forbidden)
    monkeypatch.setattr(artifacts, "read", forbidden)
    with pytest.raises(ContinuousForwardSourceError, match="SQL_SNAPSHOT_LIMIT"):
        store.resolve(complete)
    assert calls == 2


def test_final_transaction_never_hashes_the_resolved_source_graph(case, monkeypatch):
    engine, _, closure, store = case
    value = store.resolve(closure)
    store.require_resolved(value)
    monkeypatch.setattr(
        store, "_fingerprint", lambda value: pytest.fail("full graph hash under SQL")
    )
    with _repeatable_read_transaction(engine) as connection:
        store.recheck_in_transaction(connection, value)
