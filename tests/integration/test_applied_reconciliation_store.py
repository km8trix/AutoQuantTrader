"""Disposable retained metadata fixtures; production authentication remains composed."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
from threading import Barrier, Event

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.domain.account_coordinator import AccountLeaseOwnershipLost
from packages.domain.durable_journal_contracts import JournalHead, empty_head
from packages.domain.reconciliation_persistence_contracts import (
    COMMIT_SCHEMA,
    ReconciliationCommit,
    ReconciliationRetentionRead,
)
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.applied_reconciliation import (
    AppliedReconciliationConflict,
    SqlAppliedReconciliation,
    reconciliation_journal_key,
)
from packages.persistence.applied_reconciliation_schema import (
    APPLIED_RECONCILIATION_TABLES,
    applied_reconciliation_commits,
)
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import JournalConflict, SqlDurableJournal
from packages.persistence.durable_journal_schema import (
    JOURNAL_TABLES,
    journal_appends,
    journal_entries,
    journal_streams,
)
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
)
from tests.integration.test_sql_account_coordinator import MutableClock, coordinator
from tests.unit.test_reconciliation_evidence import SyntheticCapture, evidence_case

fixture_meta = sa.MetaData()
retained = sa.Table(
    "test_reconciliation_retained",
    fixture_meta,
    sa.Column("identity", sa.String(128), primary_key=True),
    sa.Column("payload", sa.LargeBinary, nullable=False),
    sa.Column("sha256", sa.String(64), nullable=False),
)
current = sa.Table(
    "test_reconciliation_current",
    fixture_meta,
    sa.Column("account_id", sa.String(128), primary_key=True),
    sa.Column("heads", sa.LargeBinary, nullable=False),
    sa.Column("transition", sa.String(128), nullable=False),
)


class RetainedFixtureReader:
    """Small retained rows, not an echo callback or provider authentication claim."""

    def __init__(self):
        self.after_read = None
        self.records = {}
        self.heads = {}

    def register(self, value, payload):
        # Fixture producer prepares actual typed metadata before any account lock.
        self.records[value.transition.command_id] = (value, payload)
        self.heads[codec.encode_record(value.current_heads)] = value.current_heads

    def read_in_transaction(
        self,
        connection,
        *,
        transition,
        sources,
        objects,
        reconciliation_key,
        reconciliation_receipt,
        fence_receipt,
    ):
        row = (
            connection.execute(
                sa.select(retained).where(retained.c.identity == transition.command_id)
            )
            .mappings()
            .one()
        )
        assert len(row["payload"]) < 16384
        if sha256(row["payload"]).hexdigest() != row["sha256"]:
            raise AppliedReconciliationConflict("FIXTURE_METADATA_CORRUPT")
        value, expected_payload = self.records[transition.command_id]
        if expected_payload != row["payload"]:
            raise AppliedReconciliationConflict("FIXTURE_METADATA_CHANGED")
        assert value.transition.account_id == fence_receipt.fence.account_id
        for source in value.sources.sources:
            actual = connection.execute(
                sa.select(journal_entries.c.payload, journal_entries.c.payload_sha256).where(
                    journal_entries.c.key_sha256 == source.key.semantic_sha256,
                    journal_entries.c.record_id == source.record_id,
                )
            ).one_or_none()
            if (
                actual is None
                or sha256(actual.payload).hexdigest() != source.evidence.object_ref.object_sha256
                or actual.payload_sha256 != source.evidence.object_ref.object_sha256
            ):
                raise AppliedReconciliationConflict("FIXTURE_SOURCE_MISSING_OR_CORRUPT")
        now = (
            connection.execute(
                sa.select(current).where(current.c.account_id == transition.account_id)
            )
            .mappings()
            .one()
        )
        heads = self.heads.get(now["heads"])
        if heads is None:
            raise AppliedReconciliationConflict("FIXTURE_HEADS_CHANGED")
        stream = (
            connection.execute(
                sa.select(journal_streams).where(
                    journal_streams.c.key_sha256 == reconciliation_key.semantic_sha256
                )
            )
            .mappings()
            .one_or_none()
        )
        journal_head = (
            empty_head(reconciliation_key)
            if stream is None
            else JournalHead(
                reconciliation_key.semantic_sha256,
                stream["last_sequence"],
                stream["last_entry_sha256"],
            )
        )
        journal = connection.execute(
            sa.select(journal_appends.c.receipt_sha256).where(
                journal_appends.c.key_sha256 == reconciliation_key.semantic_sha256,
                journal_appends.c.command_id == reconciliation_receipt.journal.command_id,
            )
        ).scalar_one_or_none()
        existing_receipt = None
        if journal is not None:
            assert journal == reconciliation_receipt.journal.semantic_sha256
            existing_receipt = reconciliation_receipt.journal
        if self.after_read is not None:
            self.after_read()
        return replace(
            value, current_heads=heads, journal_head=journal_head, journal_receipt=existing_receipt
        )


class StoreFixture:
    def __init__(self, tmp_path):
        self.engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/reconciliation.sqlite")
        metadata.create_all(
            self.engine,
            tables=(
                *JOURNAL_TABLES,
                *APPLIED_RECONCILIATION_TABLES,
                phase2_account_lease_heads,
                phase2_account_leases,
                phase2_account_lease_releases,
            ),
        )
        fixture_meta.create_all(self.engine)
        self.case = evidence_case(tmp_path)
        self.cases = []
        self.clock = MutableClock(self.case["at"])
        self.coordinator, _, self.authority = coordinator(
            self.engine, self.case["commit"].scope.account_id, clock=self.clock
        )
        self.fence = self.coordinator.acquire("fixture-owner").fence
        self.reader = RetainedFixtureReader()
        self.journal = SqlDurableJournal(
            self.engine,
            codec=codec,
            record_types={
                COMMIT_SCHEMA: ReconciliationCommit,
                "fixture-source/1": SyntheticCapture,
            },
        )
        self.store = self.store_for(self.case)
        self.retain(self.case)

    def store_for(self, case):
        self.cases.append(case)
        cases = self.cases

        class Resolver:
            def resolve(self, commit):
                source = next(item for item in cases if item["commit"].sources == commit.sources)
                return source["preparer"].resolve(commit)

        return SqlAppliedReconciliation(
            self.engine,
            coordinator=self.coordinator,
            journal=self.journal,
            codec=codec,
            evidence=Resolver(),
            reader=self.reader,
        )

    def retain(self, case):
        if self.clock.instant < case["at"]:
            self.clock.instant = case["at"]
        self.journal.append(case["source"].key, case["capture_request"])
        resolved = case["preparer"].resolve(case["commit"])
        value = ReconciliationRetentionRead(
            case["transition"],
            case["sources"],
            resolved.retained_objects,
            case["heads"],
            empty_head(reconciliation_journal_key(case["commit"].scope)),
            None,
        )
        payload = codec.encode_record(value)
        self.reader.register(value, payload)
        with _write_transaction(self.engine) as connection:
            connection.execute(
                sa.insert(retained).values(
                    identity=case["transition"].command_id,
                    payload=payload,
                    sha256=sha256(payload).hexdigest(),
                )
            )
            exists = connection.scalar(
                sa.select(current.c.account_id).where(
                    current.c.account_id == case["commit"].scope.account_id
                )
            )
            values = dict(
                heads=codec.encode_record(case["heads"]), transition=case["transition"].command_id
            )
            if exists:
                connection.execute(
                    sa.update(current).where(current.c.account_id == exists).values(**values)
                )
            else:
                connection.execute(
                    sa.insert(current).values(account_id=case["commit"].scope.account_id, **values)
                )

    def prepare(self, case=None, *, head=None, store=None):
        case, store = case or self.case, store or self.store
        previous = None
        if case["commit"].previous_commit_sha256 is not None:
            with _write_transaction(self.engine) as connection:
                snapshot = store.capture_current_in_transaction(
                    connection, scope=case["commit"].scope
                )
            previous = store.resolve_snapshot(snapshot)
        return store.prepare(
            case["commit"],
            expected_head=head or empty_head(reconciliation_journal_key(case["commit"].scope)),
            previous=previous,
        )

    def commit(self, prepared, *, store=None):
        with _write_transaction(self.engine) as connection:
            return (store or self.store).commit_in_transaction(
                connection, prepared=prepared, fence=self.fence
            )

    def snapshot(self, command_id=None):
        with _write_transaction(self.engine) as connection:
            if command_id is None:
                return self.store.capture_current_in_transaction(
                    connection, scope=self.case["commit"].scope
                )
            return self.store.capture_commit_in_transaction(
                connection, scope=self.case["commit"].scope, command_id=command_id
            )

    def counts(self):
        with self.engine.connect() as connection:
            return tuple(
                connection.scalar(sa.select(sa.func.count()).select_from(table))
                for table in (*JOURNAL_TABLES, *APPLIED_RECONCILIATION_TABLES)
            )


@pytest.fixture
def fixture(tmp_path):
    value = StoreFixture(tmp_path)
    try:
        yield value
    finally:
        value.engine.dispose()


def test_retained_fill_blocked_result_and_exact_restart_retry(fixture):
    receipt = fixture.commit(fixture.prepare())
    resolved = fixture.store.resolve_snapshot(fixture.snapshot()).resolved
    assert receipt.sequence == 1 and resolved.result.status == "blocked"
    assert resolved.transition.current.state == fixture.case["batch"].state
    assert resolved.transition.current.snapshot.trade_date_cash == 599
    assert len(resolved.applications.applications[0].journal_entry_ids) == 2
    before = fixture.counts()
    restarted = fixture.store_for(fixture.case)
    assert fixture.commit(fixture.prepare(store=restarted), store=restarted) == receipt
    assert fixture.counts() == before


def test_old_retry_after_later_commit_precedes_fresh_current_heads(fixture, tmp_path):
    first = fixture.prepare()
    receipt1 = fixture.commit(first)
    second = evidence_case(tmp_path, index=1, previous=fixture.case, effect=1)
    fixture.retain(second)
    store = fixture.store_for(second)
    receipt2 = fixture.commit(
        fixture.prepare(second, head=receipt1.journal.committed_head, store=store), store=store
    )
    before = fixture.counts()
    assert receipt2.sequence == 2 and fixture.commit(first) == receipt1
    assert fixture.counts() == before
    assert fixture.store._decode(fixture.snapshot(first.resolved.commit.command_id)) == receipt1
    assert fixture.store._decode(fixture.snapshot()) == receipt2
    resolved1 = fixture.store.resolve_snapshot(fixture.snapshot(first.resolved.commit.command_id))
    resolved2 = fixture.store.resolve_snapshot(fixture.snapshot())
    with _write_transaction(fixture.engine) as connection:
        page = fixture.store.capture_page_in_transaction(connection, through=resolved1)
        second_page = fixture.store.capture_page_in_transaction(
            connection, through=resolved2, after=resolved1, limit=1
        )
    assert tuple(fixture.store._decode(item) for item in page) == (receipt1,)
    assert tuple(fixture.store._decode(item) for item in second_page) == (receipt2,)


def test_changed_same_command_rejects_without_new_rows(fixture, tmp_path):
    original = fixture.prepare()
    fixture.commit(original)
    changed_case = evidence_case(tmp_path, index=1)
    changed_case["commit"] = replace(
        changed_case["commit"], command_id=fixture.case["commit"].command_id
    )
    fixture.retain(changed_case)
    store = fixture.store_for(changed_case)
    changed = fixture.prepare(changed_case, store=store)
    before = fixture.counts()
    with pytest.raises(AppliedReconciliationConflict, match="IMMUTABLE_RETRY_CONFLICT"):
        fixture.commit(changed, store=store)
    assert fixture.counts() == before


@pytest.mark.parametrize("change", ["heads", "source", "object", "transition"])
def test_changed_current_or_retained_metadata_rejects(fixture, change):
    prepared, before = fixture.prepare(), fixture.counts()
    with _write_transaction(fixture.engine) as connection:
        if change == "heads":
            connection.execute(
                sa.update(current).values(
                    heads=codec.encode_record(replace(fixture.case["heads"], effect_watermark=1))
                )
            )
        elif change == "source":
            connection.execute(sa.update(journal_entries).values(payload=b"changed"))
        else:
            row = connection.execute(sa.select(retained)).mappings().one()
            value = codec.decode_record(row["payload"], ReconciliationRetentionRead)
            value = (
                replace(value, objects=value.objects[:-1])
                if change == "object"
                else replace(value, transition=replace(value.transition, command_sha256="f" * 64))
            )
            payload = codec.encode_record(value)
            connection.execute(
                sa.update(retained).values(payload=payload, sha256=sha256(payload).hexdigest())
            )
    with pytest.raises(AppliedReconciliationConflict):
        fixture.commit(prepared)
    assert fixture.counts() == before


def test_expiry_during_recheck_rolls_back_journal_and_index(fixture):
    prepared, before = fixture.prepare(), fixture.counts()
    fixture.reader.after_read = lambda: fixture.clock.advance(timedelta(minutes=1))
    with pytest.raises(AccountLeaseOwnershipLost):
        fixture.commit(prepared)
    assert fixture.counts() == before


def test_outer_failure_rolls_back_canonical_transition_and_provenance(fixture):
    prepared, before = fixture.prepare(), fixture.counts()
    with pytest.raises(RuntimeError), _write_transaction(fixture.engine) as connection:
        connection.execute(sa.update(current).values(transition="prospective-transition"))
        fixture.store.commit_in_transaction(connection, prepared=prepared, fence=fixture.fence)
        raise RuntimeError("fixture late outer failure")
    assert fixture.counts() == before
    with fixture.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(current.c.transition))
            == fixture.case["transition"].command_id
        )


def test_late_index_failure_rolls_back_journal_savepoint(fixture):
    prepared, before = fixture.prepare(), fixture.counts()

    def reject(connection, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO personal_reconciliation_commits"):
            raise RuntimeError("fixture index failure")

    sa.event.listen(fixture.engine, "before_cursor_execute", reject)
    try:
        with pytest.raises(RuntimeError):
            fixture.commit(prepared)
    finally:
        sa.event.remove(fixture.engine, "before_cursor_execute", reject)
    assert fixture.counts() == before


def test_active_transaction_and_owned_preparation_required(fixture):
    prepared = fixture.prepare()
    with fixture.engine.connect() as connection:
        with pytest.raises(AppliedReconciliationConflict, match="ACTIVE_TRANSACTION"):
            fixture.store.commit_in_transaction(connection, prepared=prepared, fence=fixture.fence)
        connection.begin()
        with pytest.raises(AppliedReconciliationConflict, match="EXPLICIT_TRANSACTION"):
            fixture.store.commit_in_transaction(connection, prepared=prepared, fence=fixture.fence)
    with (
        _write_transaction(fixture.engine) as connection,
        pytest.raises(AppliedReconciliationConflict, match="OWNED_PREPARATION"),
    ):
        fixture.store_for(fixture.case).commit_in_transaction(
            connection, prepared=prepared, fence=fixture.fence
        )


def test_prepared_mutation_rejects(fixture):
    with pytest.raises(AppliedReconciliationConflict, match="PREPARATION_CHANGED"):
        fixture.commit(replace(fixture.prepare(), payload=b"altered"))


def test_two_identical_writers_return_one_original_receipt(fixture):
    pending, barrier = fixture.prepare(), Barrier(2)

    def write(_):
        barrier.wait(timeout=5)
        return fixture.commit(pending)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(write, range(2)))
    assert results[0] == results[1] and fixture.counts()[-1] == 1


def test_insert_returning_does_not_depend_on_rowcount(fixture):
    def unknown(connection, statement, multiparams, params, options, result):
        if statement.is_insert:
            result.rowcount = -1

    sa.event.listen(fixture.engine, "after_execute", unknown)
    try:
        prepared = fixture.prepare()
        assert fixture.commit(prepared) == fixture.commit(prepared)
    finally:
        sa.event.remove(fixture.engine, "after_execute", unknown)


def test_detached_slow_validation_allows_writer_commit(fixture):
    receipt = fixture.commit(fixture.prepare())
    snapshot, evidence = fixture.snapshot(), fixture.store.evidence
    entered, finish = Event(), Event()

    class Paused:
        def resolve(self, commit):
            entered.set()
            assert finish.wait(timeout=5)
            return evidence.resolve(commit)

    fixture.store.evidence = Paused()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fixture.store.resolve_snapshot, snapshot)
        assert entered.wait(timeout=5)
        try:
            with _write_transaction(fixture.engine) as connection:
                connection.execute(sa.update(current).values(transition="writer-committed"))
            with fixture.engine.connect() as connection:
                assert connection.scalar(sa.select(current.c.transition)) == "writer-committed"
        finally:
            finish.set()
        assert future.result(timeout=5).receipt == receipt


def test_changed_snapshot_and_corrupt_mirrors_reject(fixture):
    fixture.commit(fixture.prepare())
    snapshot = fixture.snapshot()
    resolved = fixture.store.resolve_snapshot(snapshot)
    with _write_transaction(fixture.engine) as connection:
        connection.execute(sa.update(applied_reconciliation_commits).values(commit_sha256="e" * 64))
    with (
        _write_transaction(fixture.engine) as connection,
        pytest.raises(AppliedReconciliationConflict, match="SNAPSHOT_CHANGED"),
    ):
        fixture.store.recheck_snapshot_in_transaction(
            connection, resolved=resolved, fence=fixture.fence
        )
    with pytest.raises(AppliedReconciliationConflict, match="RETAINED_COMMIT_INVALID"):
        fixture.store.resolve_snapshot(fixture.snapshot())


def test_missing_index_with_retained_journal_rejects_partial_restore(fixture):
    pending = fixture.prepare()
    fixture.commit(pending)
    with _write_transaction(fixture.engine) as connection:
        connection.execute(sa.delete(applied_reconciliation_commits))
    before = fixture.counts()
    with pytest.raises((AppliedReconciliationConflict, JournalConflict)):
        fixture.commit(pending)
    assert fixture.counts() == before


def test_current_snapshot_recheck_authenticates_source_retention(fixture):
    fixture.commit(fixture.prepare())
    snapshot = fixture.snapshot()
    resolved = fixture.store.resolve_snapshot(snapshot)
    with _write_transaction(fixture.engine) as connection:
        actual = fixture.store.recheck_snapshot_in_transaction(
            connection, resolved=resolved, fence=fixture.fence
        )
    assert actual.current_heads == fixture.case["heads"]
    with _write_transaction(fixture.engine) as connection:
        connection.execute(
            sa.delete(journal_entries).where(
                journal_entries.c.key_sha256 == fixture.case["source"].key.semantic_sha256
            )
        )
    with (
        _write_transaction(fixture.engine) as connection,
        pytest.raises(AppliedReconciliationConflict, match="SOURCE_MISSING"),
    ):
        fixture.store.recheck_snapshot_in_transaction(
            connection, resolved=resolved, fence=fixture.fence
        )


@pytest.mark.parametrize("field", ["commit_sha256", "command_id", "sequence"])
def test_corrupt_sqlite_metadata_is_capped_before_decode(fixture, field):
    fixture.commit(fixture.prepare())
    with _write_transaction(fixture.engine) as connection:
        connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            sa.update(applied_reconciliation_commits).values(**{field: "x" * (1024 * 1024)})
        )
        connection.exec_driver_sql("PRAGMA ignore_check_constraints=OFF")
    snapshot = fixture.snapshot()
    if field == "sequence":
        assert snapshot.row[field] is None
    else:
        assert len(snapshot.row[field]) == (65 if field == "commit_sha256" else 129)
    with pytest.raises(AppliedReconciliationConflict, match="RETAINED_COMMIT_INVALID"):
        fixture.store.resolve_snapshot(snapshot)


def test_scope_and_foreign_database_are_rejected(fixture, tmp_path):
    prepared = fixture.prepare()
    with (
        _write_transaction(fixture.engine) as connection,
        pytest.raises(AppliedReconciliationConflict, match="ACCOUNT_FENCE_SCOPE"),
    ):
        fixture.store.commit_in_transaction(
            connection, prepared=prepared, fence=replace(fixture.fence, account_id="foreign")
        )
    other = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/foreign.sqlite")
    try:
        with (
            _write_transaction(other) as connection,
            pytest.raises(AppliedReconciliationConflict, match="SAME_ENGINE"),
        ):
            fixture.store.commit_in_transaction(connection, prepared=prepared, fence=fixture.fence)
    finally:
        other.dispose()


def test_competing_different_first_commands_have_one_winner(fixture):
    first = fixture.prepare()
    second = fixture.store.prepare(
        replace(fixture.case["commit"], command_id="competing-command"),
        expected_head=first.receipt.journal.previous_head,
        previous=None,
    )
    barrier = Barrier(2)

    def write(prepared):
        barrier.wait(timeout=5)
        try:
            return fixture.commit(prepared)
        except AppliedReconciliationConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(write, (first, second)))
    assert sum(result is not None for result in results) == 1
    assert fixture.counts()[-1] == 1


def test_future_comparison_cannot_be_published_by_an_earlier_fence(fixture, tmp_path):
    first = fixture.commit(fixture.prepare())
    earlier = fixture.clock.instant
    second = evidence_case(tmp_path, index=1, previous=fixture.case)
    fixture.retain(second)
    fixture.clock.instant = earlier
    store = fixture.store_for(second)
    pending = fixture.prepare(second, head=first.journal.committed_head, store=store)
    before = fixture.counts()
    with pytest.raises(AppliedReconciliationConflict, match="CURRENT_ACCOUNT_HEADS"):
        fixture.commit(pending, store=store)
    assert fixture.counts() == before


@pytest.mark.parametrize("operation", ["genesis", "retry", "continuation", "recheck", "page"])
def test_fenced_paths_never_call_injected_codec_or_evidence(
    fixture, tmp_path, monkeypatch, operation
):
    pending = fixture.prepare()
    resolved, store = None, fixture.store
    if operation != "genesis":
        fixture.commit(pending)
        resolved = store.resolve_snapshot(fixture.snapshot())
    if operation == "continuation":
        second = evidence_case(tmp_path, index=1, previous=fixture.case)
        fixture.retain(second)
        store = fixture.store_for(second)
        pending = fixture.prepare(second, head=pending.receipt.journal.committed_head, store=store)

    def forbidden(*args, **kwargs):
        raise AssertionError("injected replay called under SQL transaction")

    # The journal, compact-receipt codec and fixture source reader share this module.
    monkeypatch.setattr(codec, "encode_record", forbidden)
    monkeypatch.setattr(codec, "decode_record", forbidden)
    monkeypatch.setattr(store.evidence, "resolve", forbidden)
    if operation in ("genesis", "retry", "continuation"):
        assert fixture.commit(pending, store=store) == pending.receipt
    else:
        with _write_transaction(fixture.engine) as connection:
            if operation == "recheck":
                actual = store.recheck_snapshot_in_transaction(
                    connection, resolved=resolved, fence=fixture.fence
                )
                assert actual.transition == fixture.case["transition"]
            else:
                page = store.capture_page_in_transaction(connection, through=resolved)
                assert tuple(row.row["sequence"] for row in page) == (1,)


def test_detached_stalled_receipt_decoder_does_not_hold_writer_commit(fixture):
    receipt = fixture.commit(fixture.prepare())
    snapshot = fixture.snapshot()
    entered, release = Event(), Event()

    class PausedCodec:
        encode_record = staticmethod(codec.encode_record)

        @staticmethod
        def decode_record(payload, expected_type):
            entered.set()
            assert release.wait(timeout=5)
            return codec.decode_record(payload, expected_type)

    fixture.store.codec = PausedCodec()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fixture.store.resolve_snapshot, snapshot)
        assert entered.wait(timeout=5)
        try:
            with _write_transaction(fixture.engine) as connection:
                connection.execute(sa.update(current).values(transition="decoder-overlap-commit"))
            with fixture.engine.connect() as connection:
                assert (
                    connection.scalar(sa.select(current.c.transition)) == "decoder-overlap-commit"
                )
            assert not future.done()
        finally:
            release.set()
        assert future.result(timeout=5).receipt == receipt


@pytest.mark.parametrize("field", ["canonical_payload", "commit_sha256", "journal_receipt_sha256"])
def test_exact_prior_snapshot_is_rechecked_before_continuation(fixture, tmp_path, field):
    first = fixture.commit(fixture.prepare())
    second = evidence_case(tmp_path, index=1, previous=fixture.case)
    fixture.retain(second)
    store = fixture.store_for(second)
    pending = fixture.prepare(second, head=first.journal.committed_head, store=store)
    with _write_transaction(fixture.engine) as connection:
        connection.execute(
            sa.update(applied_reconciliation_commits).values(
                **{field: b"changed" if field == "canonical_payload" else "a" * 64}
            )
        )
    before = fixture.counts()
    with pytest.raises(AppliedReconciliationConflict, match="CURRENT_RECONCILIATION_PREFIX"):
        fixture.commit(pending, store=store)
    assert fixture.counts() == before


def test_prior_wrapper_required_and_owned_before_preparation(fixture, tmp_path):
    first = fixture.commit(fixture.prepare())
    second = evidence_case(tmp_path, index=1, previous=fixture.case)
    fixture.retain(second)
    store = fixture.store_for(second)
    with pytest.raises(AppliedReconciliationConflict, match="PREPARED_RECONCILIATION_PREFIX"):
        store.prepare(second["commit"], expected_head=first.journal.committed_head, previous=None)
    foreign = fixture.store.resolve_snapshot(fixture.snapshot())
    with pytest.raises(AppliedReconciliationConflict, match="OWNED_RESOLVED"):
        store.prepare(
            second["commit"], expected_head=first.journal.committed_head, previous=foreign
        )
    own = store.resolve_snapshot(fixture.snapshot())
    with pytest.raises(AppliedReconciliationConflict, match="RESOLVED_SNAPSHOT_CHANGED"):
        store.prepare(
            second["commit"],
            expected_head=first.journal.committed_head,
            previous=replace(own, row_values={}),
        )


def test_owned_snapshot_recheck_and_page_reject_changed_anchors(fixture):
    fixture.commit(fixture.prepare())
    resolved = fixture.store.resolve_snapshot(fixture.snapshot())
    with (
        _write_transaction(fixture.engine) as connection,
        pytest.raises(AppliedReconciliationConflict, match="RESOLVED_SNAPSHOT_CHANGED"),
    ):
        fixture.store.recheck_snapshot_in_transaction(
            connection, resolved=replace(resolved, row_values={}), fence=fixture.fence
        )
    with _write_transaction(fixture.engine) as connection:
        connection.execute(
            sa.update(applied_reconciliation_commits).values(canonical_payload=b"changed")
        )
    with (
        _write_transaction(fixture.engine) as connection,
        pytest.raises(AppliedReconciliationConflict, match="HISTORY_PAGE_ANCHOR_CHANGED"),
    ):
        fixture.store.capture_page_in_transaction(connection, through=resolved)
