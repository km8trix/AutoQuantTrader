"""Actual disposable SQL publication; all source/clock/response evidence is synthetic."""

import copy
import pickle
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Event
from uuid import uuid4

import pytest
import sqlalchemy as sa

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application import personal_forward_capture as capture_module
from packages.application.personal_forward_capture import (
    ForwardCaptureError,
    capture_forward,
    replay_capture,
)
from packages.domain.durable_journal_contracts import empty_head
from packages.domain.forward_capture_contracts import (
    CAPTURE_SCHEMA,
    CaptureVerification,
    ForwardCaptureRecord,
    ForwardCaptureRequest,
)
from packages.domain.forward_contracts import ForwardDataState
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import (
    JOURNAL_TABLES,
    journal_appends,
    journal_entries,
    journal_streams,
)
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication
from packages.persistence.schema import metadata
from tests.integration.test_personal_forward_capture_journal import retained as retained
from tests.integration.test_phase2_postgres_exit import postgres_engine as postgres_engine
from tests.unit.test_personal_forward_capture import AT, Clock, Transport, Verifier, request


class Case:
    def __init__(self, retained, *, stage=None, milliseconds=3000):
        self.engine, self.real_objects, _ = retained
        self.request, self.clock, self.verifier, self.transport = (
            request(),
            Clock(),
            Verifier(),
            Transport(),
        )
        self.state = ForwardDataState((self.request.source,), "recorded")
        self.expected_head = empty_head(self.request.journal_key)
        self.triggered, self.in_sql, self.committed = False, False, False
        self.purity_guard = False
        active_connections: set[sa.Connection] = set()

        def trigger(which):
            if stage == which and not self.triggered:
                self.triggered = True
                self.clock.advance(milliseconds=milliseconds)

        def outside():
            if self.purity_guard:
                assert not self.in_sql and not self.committed, "codec/artifact after SQL boundary"

        class Objects:
            def put(inner, *args, **kwargs):
                outside()
                result = self.real_objects.put(*args, **kwargs)
                trigger("put")
                return result

            def read(inner, *args, **kwargs):
                outside()
                result = self.real_objects.read(*args, **kwargs)
                trigger("read")
                return result

        class Codec:
            def encode_record(inner, value):
                outside()
                result = personal_codec.encode_record(value)
                if type(value) is ForwardCaptureRecord:
                    trigger("encode")
                return result

            def decode_record(inner, value, expected):
                outside()
                result = personal_codec.decode_record(value, expected)
                if expected is ForwardCaptureRecord:
                    trigger("decode")
                return result

        self.objects, self.codec = Objects(), Codec()
        self.journal = SqlDurableJournal(
            self.engine, codec=self.codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
        )
        original_prepare = self.journal.prepare_append
        original_readback = self.journal.recheck_prepared_append_in_transaction

        def prepare(*args):
            result = original_prepare(*args)
            trigger("prepare")
            return result

        self.after_readback = lambda: None
        self.before_readback = lambda connection, prepared: None

        def readback(*args, **kwargs):
            self.before_readback(*args)
            result = original_readback(*args, **kwargs)
            assert args[0] in active_connections and self.in_sql
            trigger("readback")
            self.after_readback()
            return result

        self.journal.prepare_append = prepare
        self.journal.recheck_prepared_append_in_transaction = readback
        self.publisher = SqlForwardCapturePublication(self.engine, journal=self.journal)

        @sa.event.listens_for(self.engine, "begin")
        def begin(connection):
            active_connections.add(connection)
            self.in_sql = True
            if self.clock.calls == 3:
                trigger("begin")

        @sa.event.listens_for(self.engine, "commit")
        def commit(connection):
            active_connections.discard(connection)
            self.in_sql = bool(active_connections)
            self.committed = True

        @sa.event.listens_for(self.engine, "rollback")
        def rollback(connection):
            active_connections.discard(connection)
            self.in_sql = bool(active_connections)

        @sa.event.listens_for(self.engine, "after_cursor_execute")
        def after_sql(connection, cursor, statement, parameters, context, executemany):
            compiled = context.compiled
            if (
                compiled is not None
                and getattr(compiled.statement, "is_insert", False)
                and getattr(compiled.statement, "table", None) is journal_entries
            ):
                trigger("insert")

    def capture(self, **changes):
        return capture_forward(
            self.request,
            self.state,
            expected_head=self.expected_head,
            clock=self.clock,
            verifier=self.verifier,
            transport=self.transport,
            journal=self.journal,
            artifacts=self.objects,
            codec=self.codec,
            publisher=changes.get("publisher", self.publisher),
        )

    def assert_empty(self):
        self.purity_guard = False
        with self.engine.connect() as connection:
            for table in JOURNAL_TABLES:
                assert connection.scalar(sa.select(sa.func.count()).select_from(table)) == 0
        assert self.journal.read_receipt(self.request.journal_key, self.request.capture_id) is None
        assert self.journal.read_head(self.request.journal_key) == empty_head(
            self.request.journal_key
        )


@pytest.mark.parametrize(
    "stage", ["put", "read", "encode", "decode", "prepare", "begin", "insert", "readback"]
)
def test_original_deadline_after_each_boundary_has_no_retained_capture(retained, stage):
    case = Case(retained, stage=stage)
    with pytest.raises(ForwardCaptureError, match="ORIGINAL_DEADLINE"):
        case.capture()
    assert case.triggered and not case.committed
    case.assert_empty()


@pytest.mark.parametrize(
    "field", ["first_expiry", "request", "source", "instrument", "publication", "publisher"]
)
def test_nested_mutation_after_actual_final_readback_rolls_back(retained, field):
    case = Case(retained)

    def mutate():
        state = next(iter(capture_module._EPISODE_STATES.values()))
        record = state.publication.record
        if field == "first_expiry":
            object.__setattr__(
                record.verifications[0],
                "valid_until",
                record.verifications[0].valid_until + timedelta(days=1),
            )
        elif field == "request":
            object.__setattr__(case.request, "deadline_ms", 2999)
        elif field == "source":
            object.__setattr__(case.request.source, "rights_reference", "changed")
        elif field == "instrument":
            object.__setattr__(case.request.instruments[0], "identity_reference", "changed")
        elif field == "publication":
            object.__setattr__(
                record.observations[0].payload,
                "bid",
                record.observations[0].payload.bid + 1,
            )
        else:
            case.publisher.journal = copy.copy(case.journal)

    case.after_readback = mutate
    with pytest.raises(ForwardCaptureError, match="ORIGINAL"):
        case.capture()
    assert not case.committed
    case.assert_empty()


def test_no_codec_artifact_or_full_source_hash_under_sql_or_after_commit(retained, monkeypatch):
    case = Case(retained)
    case.purity_guard = True
    for kind in (
        ForwardCaptureRequest,
        ForwardDataState,
        ForwardCaptureRecord,
        CaptureVerification,
    ):
        original = kind.semantic_sha256

        def digest(value, property=original):
            assert not case.in_sql and not case.committed
            return property.__get__(value, type(value))

        monkeypatch.setattr(kind, "semantic_sha256", property(digest))
    result = case.capture()
    assert case.committed and result.record.request.evidence_class == "synthetic_fixture"
    assert case.clock.calls == 3 and len(result.record.verifications) == 3


@pytest.mark.parametrize("milliseconds", [100, 101])
def test_later_verification_cannot_renew_first_original_expiry(retained, milliseconds):
    case = Case(retained, stage="readback", milliseconds=milliseconds)
    real = case.verifier.verify

    def verify(req, sample):
        proof = real(req, sample)
        if len(case.verifier.calls) == 1:
            return replace(proof, valid_until=sample.at + timedelta(milliseconds=300))
        return proof

    case.verifier.verify = verify
    with pytest.raises(ForwardCaptureError, match="ORIGINAL_DEADLINE"):
        case.capture()
    assert case.triggered
    case.assert_empty()


@pytest.mark.parametrize("target", ["entry", "append", "head"])
def test_actual_original_journal_readback_rejects_tamper_without_repair(retained, target):
    case = Case(retained)
    touched = []

    def corrupt(connection, prepared):
        if target == "entry":
            statement = sa.delete(journal_entries)
        elif target == "append":
            statement = sa.update(journal_appends).values(command_sha256="f" * 64)
        else:
            statement = sa.update(journal_streams).values(last_entry_sha256="f" * 64)
        touched.append(connection.execute(statement).rowcount)

    case.before_readback = corrupt
    with pytest.raises(ForwardCaptureError):
        case.capture()
    assert touched == [1] and not case.committed
    case.assert_empty()


@pytest.mark.parametrize("fault", ["boot", "utc_regression", "monotonic_regression"])
def test_final_current_clock_cannot_replace_original_epoch_or_regress(retained, fault):
    case = Case(retained)

    def change():
        values = {
            "boot": {"boot_id": "changed-epoch"},
            "utc_regression": {"at": case.clock.latest.at - timedelta(seconds=1)},
            "monotonic_regression": {"monotonic_ns": case.clock.latest.monotonic_ns - 1},
        }
        case.clock.latest = replace(case.clock.latest, **values[fault])

    case.after_readback = change
    with pytest.raises(ForwardCaptureError, match="ORIGINAL_DEADLINE"):
        case.capture()
    case.assert_empty()


def test_first_verifier_delay_spends_original_process_budget_before_http(retained, monkeypatch):
    case = Case(retained)
    actual_ns = [1_000_000_000]
    monkeypatch.setattr(capture_module, "_MONOTONIC_NS", lambda: actual_ns[0])
    real = case.verifier.verify

    def delayed(req, sample):
        proof = real(req, sample)
        actual_ns[0] += 3_000_000_000
        return proof

    case.verifier.verify = delayed
    with pytest.raises(ForwardCaptureError, match="ORIGINAL_DEADLINE"):
        case.capture()
    assert case.transport.calls == 0 and case.clock.calls == 1
    case.assert_empty()


def test_initial_clock_callback_cannot_change_original_source_before_first_verification(retained):
    case = Case(retained)
    original = case.clock.sample

    def sample():
        result = original()
        object.__setattr__(case.request.source, "rights_reference", "different-original")
        return result

    case.clock.sample = sample
    with pytest.raises(ForwardCaptureError, match="ORIGINAL_INPUT"):
        case.capture()
    assert not case.verifier.calls and case.transport.calls == 0
    case.assert_empty()


@pytest.mark.parametrize("cutoff", ["verification", "window"])
def test_work_after_final_utc_sample_still_obeys_earliest_original_expiry(
    retained, monkeypatch, cutoff
):
    case = Case(retained)
    process_ns = [1_000_000_000]
    monkeypatch.setattr(capture_module, "_MONOTONIC_NS", lambda: process_ns[0])
    if cutoff == "window":
        case.request = replace(case.request, window_end=AT + timedelta(milliseconds=300))
    else:
        original_verifier = case.verifier.verify

        def verifier(req, sample):
            value = original_verifier(req, sample)
            if len(case.verifier.calls) == 1:
                return replace(value, valid_until=sample.at + timedelta(milliseconds=300))
            return value

        case.verifier.verify = verifier
    final_readback, final_checks = [False], [0]
    original_owner_check = case.publisher.require_original

    def owner_check():
        original_owner_check()
        if final_readback[0]:
            final_checks[0] += 1
            if final_checks[0] == 2:
                case.clock.advance(milliseconds=101)
                process_ns[0] += 301_000_000

    case.publisher.require_original = owner_check
    case.after_readback = lambda: final_readback.__setitem__(0, True)
    with pytest.raises(ForwardCaptureError, match="ORIGINAL_DEADLINE"):
        case.capture()
    assert final_checks == [2] and not case.committed
    case.assert_empty()


def test_multibyte_original_input_is_charged_before_http_and_raw_storage(retained, monkeypatch):
    case = Case(retained)
    identity = "\U0001f600" * 2000
    assert len(identity) == 2000 and len(identity.encode("utf-8")) == 8000
    case.request = replace(
        case.request,
        instruments=(replace(case.request.instruments[0], identity_reference=identity),),
    )
    monkeypatch.setattr(capture_module, "_MAX_EPISODE_BYTES", 8000)
    with pytest.raises(ForwardCaptureError, match="EPISODE_GRAPH_LIMIT"):
        case.capture()
    assert case.clock.calls == 0 and not case.verifier.calls and case.transport.calls == 0
    assert not tuple(case.real_objects._root.rglob("*"))
    case.assert_empty()


@pytest.mark.parametrize("fault", ["missing", "copy", "journal", "provider"])
def test_new_capture_without_original_publisher_or_source_bridge_has_no_effect(retained, fault):
    case = Case(retained)
    publisher = case.publisher
    if fault == "missing":
        publisher = None
    elif fault == "copy":
        with pytest.raises(TypeError):
            copy.copy(publisher)
        cloned = object.__new__(type(publisher))
        cloned.__dict__.update(publisher.__dict__)
        publisher = cloned
    elif fault == "journal":
        publisher.journal = copy.copy(case.journal)
    else:
        case.request = replace(case.request, evidence_class="provider_https_read")
    with pytest.raises(ForwardCaptureError, match=r"ORIGINAL_PUBLISHER|GENUINE_SOURCE_BRIDGE"):
        case.capture(publisher=publisher)
    assert case.clock.calls == 0 and not case.verifier.calls and case.transport.calls == 0
    case.assert_empty()


@pytest.mark.parametrize("fault", ["copy", "seal", "foreign"])
def test_original_episode_cannot_be_copied_corrupted_or_given_to_foreign_owner(retained, fault):
    case = Case(retained)
    real = case.publisher.publish

    def publish(episode):
        with pytest.raises(TypeError):
            pickle.dumps(episode)
        if fault == "copy":
            return real(replace(episode))
        if fault == "seal":
            object.__setattr__(episode, "seal", object())
            return real(episode)
        foreign = SqlForwardCapturePublication(case.engine, journal=case.journal)
        return foreign.publish(episode)

    case.publisher.publish = publish
    with pytest.raises(ForwardCaptureError, match="ORIGINAL"):
        case.capture()
    case.assert_empty()


def test_original_retry_after_expiry_needs_no_publisher_clock_or_new_network(retained):
    case = Case(retained)
    first = case.capture()
    case.clock.advance(milliseconds=60_000)

    def forbidden():
        raise AssertionError("historical retry sampled a clock")

    case.clock.sample = case.clock.current_sample = forbidden
    assert case.capture(publisher=None) == first
    assert case.transport.calls == 1 and len(case.verifier.calls) == 3


def test_lost_commit_ack_is_read_back_only_by_original_retry(retained):
    case = Case(retained)

    @sa.event.listens_for(case.engine, "commit", once=True)
    def ambiguous(connection):
        connection.connection.driver_connection.commit()
        raise OSError("private-ambiguous-commit-sentinel")

    with pytest.raises(ForwardCaptureError) as error:
        case.capture()
    assert "private" not in str(error.value)
    case.clock.advance(milliseconds=60_000)
    found = case.capture(publisher=None)
    assert found.record.receipt.validated_monotonic_ns == 1_200_000_000
    assert case.transport.calls == 1 and case.clock.calls == 3


def test_postgres_original_deadline_is_rechecked_after_stream_lock_wait(postgres_engine, tmp_path):
    """Actual PostgreSQL row wait; fixture clock advancement grants no host authority."""
    schema = "capture_deadline_" + uuid4().hex
    with postgres_engine.begin() as connection:
        connection.execute(sa.schema.CreateSchema(schema))
    engine = postgres_engine.execution_options(schema_translate_map={None: schema})
    try:
        metadata.create_all(engine, tables=JOURNAL_TABLES)
        objects = LocalResearchArtifactStore(tmp_path / "capture-objects")
        retained = engine, objects, tmp_path
        first_case = Case(retained)
        isolation_levels = []

        def original_snapshot(connection, prepared):
            isolation_levels.append(connection.get_isolation_level())
            assert connection.get_isolation_level() == "REPEATABLE READ"

        first_case.before_readback = original_snapshot
        original = first_case.capture()
        assert isolation_levels == ["REPEATABLE READ"]
        with engine.connect() as returned:
            assert returned.get_isolation_level() == "READ COMMITTED"
        case = Case(retained)
        case.request = replace(case.request, capture_id="after-original")
        case.state = replay_capture(original.record, case.state, artifacts=objects)
        case.expected_head = original.journal_receipt.committed_head
        case.clock = Clock(original.record.receipt.requested_at + timedelta(seconds=1))
        reached_lock = Event()
        with engine.connect() as holder:
            holder.begin()
            holder.execute(sa.select(journal_streams).with_for_update()).all()

            @sa.event.listens_for(engine, "before_cursor_execute")
            def waiting(connection, cursor, statement, parameters, context, executemany):
                if "FOR UPDATE" in statement:
                    reached_lock.set()

            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(case.capture)
                try:
                    assert reached_lock.wait(timeout=2)
                    case.clock.advance(milliseconds=3000)
                finally:
                    holder.rollback()
                with pytest.raises(ForwardCaptureError, match="ORIGINAL_DEADLINE"):
                    future.result(timeout=5)
        assert case.journal.read_head(case.request.journal_key) == case.expected_head
        assert case.journal.read_receipt(case.request.journal_key, case.request.capture_id) is None
        assert case.transport.calls == 1
        with engine.connect() as connection:
            for table in JOURNAL_TABLES:
                assert connection.scalar(sa.select(sa.func.count()).select_from(table)) == 1
    finally:
        with postgres_engine.begin() as connection:
            connection.execute(sa.schema.DropSchema(schema, cascade=True))
