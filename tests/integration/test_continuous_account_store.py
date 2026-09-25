"""Actual engine/SQL/object restart; a declared metadata fixture owns no risk authority."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Barrier, Event
from uuid import uuid4
from weakref import WeakValueDictionary

import pytest
import sqlalchemy as sa

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.domain.account_coordinator import AccountLeaseOwnershipLost
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier, ContinuousDecision
from packages.domain.continuous_persistence_contracts import (
    CONTINUOUS_COMMIT_SCHEMA,
    ContinuousAccountCommit,
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.continuous_account import (
    ContinuousAccountConflict,
    ContinuousCompositionPlan,
    ContinuousCompositionSnapshot,
    PreparedContinuousComposition,
    ResolvedContinuousComposition,
    SqlContinuousAccount,
)
from packages.persistence.continuous_account_schema import (
    CONTINUOUS_ACCOUNT_TABLES,
)
from packages.persistence.continuous_account_schema import (
    continuous_account_commits as commits,
)
from packages.persistence.continuous_account_schema import (
    continuous_account_heads as heads,
)
from packages.persistence.database import _repeatable_read_transaction, create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
)
from tests.integration.test_phase2_postgres_exit import postgres_engine as postgres_engine
from tests.integration.test_sql_account_coordinator import MutableClock, coordinator
from tests.unit.test_continuous_account_transition import preparer
from tests.unit.test_continuous_source_events import project, setup

fixture_metadata = sa.MetaData()
fixture_heads = sa.Table(
    "test_continuous_heads",
    fixture_metadata,
    sa.Column("account_id", sa.String(128), primary_key=True),
    sa.Column("payload", sa.LargeBinary, nullable=False),
)
fixture_evidence = sa.Table(
    "test_continuous_evidence",
    fixture_metadata,
    sa.Column("command_id", sa.String(128), primary_key=True),
    sa.Column("source_sha256", sa.String(64), nullable=False),
    sa.Column("decision_sha256", sa.String(64), nullable=False),
)


class RetainedMetadataComposer:
    """SQL-backed zero-admission fixture, explicitly not the production composer."""

    def __init__(self, engine, artifacts):
        self.engine, self.artifacts = engine, artifacts
        self.seal = object()
        self.owned = WeakValueDictionary()
        self.applied = 0
        self.after_apply = None
        self.resolve_hook = None

    def own(self, value):
        self.owned[id(value)] = value
        return value

    def require_prepared(self, value):
        assert type(value) is PreparedContinuousComposition and self.owned.get(id(value)) is value

    def require_resolved(self, value):
        assert type(value) is ResolvedContinuousComposition and self.owned.get(id(value)) is value

    def prepare(self, transition, *, previous, source_evidence, admissions):
        if admissions or any(d.installed_commitments for d in transition.new_decisions):
            raise ValueError("FIXTURE_UNSUPPORTED_HOLD_OR_ADMISSION")
        with _repeatable_read_transaction(self.engine) as connection:
            before = connection.scalar(sa.select(fixture_heads.c.payload))
        expected = codec.decode_record(before, ReconciliationHeads)
        actual = transition.checkpoint.current.snapshot
        result = replace(
            expected, ledger_sha256=actual.journal_sha256, order_sha256=actual.order_sha256
        )
        decisions = codec.encode_record(transition.new_decisions)
        ref = self.artifacts.put(decisions)
        evidence = ContinuousEvidenceRef(
            "fixture-decisions/1", ref, content_digest(transition.new_decisions)
        )
        retained = dict(
            command_id=transition.command_id,
            source_sha256=source_evidence.object_ref.object_sha256,
            decision_sha256=ref.object_sha256,
        )
        with _write_transaction(self.engine) as connection:
            connection.execute(sa.insert(fixture_evidence).values(**retained))
        return self.own(
            PreparedContinuousComposition(
                expected,
                result,
                source_evidence,
                evidence,
                (),
                (before, codec.encode_record(result), retained),
                self.seal,
            )
        )

    def prepare_capture(self, commit, *, previous):
        return self.own(ContinuousCompositionPlan(commit.semantic_sha256, commit, self.seal))

    def capture_in_transaction(self, connection, *, commit, plan):
        assert self.owned.get(id(plan)) is plan and plan.state == commit
        row = (
            connection.execute(
                sa.select(fixture_evidence).where(
                    fixture_evidence.c.command_id == commit.transition.command_id,
                )
            )
            .mappings()
            .one()
        )
        return self.own(ContinuousCompositionSnapshot(commit.semantic_sha256, dict(row), self.seal))

    def resolve(self, snapshot, *, commit, checkpoint, request, previous):
        assert self.owned.get(id(snapshot)) is snapshot
        if self.resolve_hook is not None:
            self.resolve_hook()
        row = snapshot.state
        assert row["source_sha256"] == commit.source_evidence.object_ref.object_sha256
        assert row["decision_sha256"] == commit.decision_evidence.object_ref.object_sha256
        source = codec.decode_record(
            self.artifacts.read(commit.source_evidence.object_ref), VersionPin
        )
        assert source.semantic_sha256 == commit.source_evidence.semantic_sha256
        decisions = codec.decode_record(
            self.artifacts.read(commit.decision_evidence.object_ref), tuple[ContinuousDecision, ...]
        )
        assert not decisions and commit.decision_evidence.semantic_sha256 == content_digest(
            decisions
        )
        assert not checkpoint.runtime_decisions
        return self.own(
            ResolvedContinuousComposition(
                commit.semantic_sha256,
                (row, codec.encode_record(commit.transition.resulting_heads)),
                self.seal,
            )
        )

    def recheck_in_transaction(self, connection, resolved, *, require_current):
        self.require_resolved(resolved)
        row, head = resolved.state
        actual = (
            connection.execute(
                sa.select(fixture_evidence).where(
                    fixture_evidence.c.command_id == row["command_id"],
                )
            )
            .mappings()
            .one()
        )
        if dict(actual) != row:
            raise ValueError("FIXTURE_SOURCE_METADATA_CHANGED")
        if require_current and connection.scalar(sa.select(fixture_heads.c.payload)) != head:
            raise ValueError("FIXTURE_CURRENT_HEADS_CHANGED")

    def apply_in_transaction(self, connection, prepared, *, fence, fence_receipt):
        self.require_prepared(prepared)
        before, after, retained = prepared.state
        if connection.scalar(sa.select(fixture_heads.c.payload)) != before:
            raise ValueError("FIXTURE_CURRENT_HEADS_CHANGED")
        actual = (
            connection.execute(
                sa.select(fixture_evidence).where(
                    fixture_evidence.c.command_id == retained["command_id"],
                )
            )
            .mappings()
            .one()
        )
        if dict(actual) != retained:
            raise ValueError("FIXTURE_SOURCE_METADATA_CHANGED")
        connection.execute(sa.update(fixture_heads).values(payload=after))
        self.applied += 1
        if self.after_apply is not None:
            self.after_apply()
        return prepared.resulting_heads


class Harness:
    def __init__(self, tmp_path, engine=None):
        self.engine = (
            engine
            if engine is not None
            else create_database_engine(f"sqlite+pysqlite:///{tmp_path}/continuous.sqlite")
        )
        metadata.create_all(
            self.engine,
            tables=(
                *JOURNAL_TABLES,
                *CONTINUOUS_ACCOUNT_TABLES,
                phase2_account_lease_heads,
                phase2_account_leases,
                phase2_account_lease_releases,
            ),
        )
        fixture_metadata.create_all(self.engine)
        cp, self.sources = setup(recorded=False)
        self.preparer = preparer(cp.inputs)
        self.first = self.preparer.prepare_initialize(
            command_id="initialize",
            inputs=cp.inputs,
            source_closure_sha256=content_digest(cp.inputs.bootstrap_events),
        )
        self.scope = ContinuousAccountScope(
            cp.inputs.spec.account_id,
            cp.inputs.spec.account_binding_sha256,
            cp.inputs.spec.deployment_id,
        )
        self.clock = MutableClock(self.first.checkpoint.now)
        self.coordinator, _, self.authority = coordinator(
            self.engine, self.scope.account_id, clock=self.clock
        )
        self.fence = self.coordinator.acquire("fixture-owner").fence
        self.artifacts = LocalResearchArtifactStore(tmp_path / "objects")
        self.composer = RetainedMetadataComposer(self.engine, self.artifacts)
        self.journal = SqlDurableJournal(
            self.engine,
            codec=codec,
            record_types={
                CONTINUOUS_COMMIT_SCHEMA: ContinuousAccountCommit,
            },
        )
        self.store = self.new_store()
        source = VersionPin("declared-synthetic-source", "1", "b" * 64)
        self.source = ContinuousEvidenceRef(
            "fixture-source/1",
            self.artifacts.put(codec.encode_record(source)),
            source.semantic_sha256,
        )
        snapshot = self.first.checkpoint.current.snapshot
        initial_heads = ReconciliationHeads(
            snapshot.journal_sha256,
            snapshot.order_sha256,
            content_digest(()),
            0,
            content_digest(()),
            0,
            self.fence.fencing_generation,
        )
        with _write_transaction(self.engine) as connection:
            connection.execute(
                sa.insert(fixture_heads).values(
                    account_id=self.scope.account_id, payload=codec.encode_record(initial_heads)
                )
            )

    def new_store(self):
        return SqlContinuousAccount(
            self.engine,
            coordinator=self.coordinator,
            journal=self.journal,
            artifacts=self.artifacts,
            codec=codec,
            preparer=self.preparer,
            composer=self.composer,
        )

    def prepare(self, transition=None, previous=None):
        return self.store.prepare(
            transition or self.first,
            scope=self.scope,
            previous=previous,
            source_evidence=self.source,
        )

    def publish(self, prepared):
        with self.store.write_transaction() as connection:
            return self.store.commit_in_transaction(connection, prepared=prepared, fence=self.fence)

    def next(self, previous, command="next"):
        self.clock.advance(timedelta(seconds=1))
        frontier = ClosedEngineFrontier(
            frontier_id=command,
            stream_id=previous.checkpoint.inputs.spec.run_id,
            previous_checkpoint_sha256=previous.checkpoint.semantic_sha256,
            source_frontier_sha256=content_digest((command, "empty-observed-closure")),
            knowledge_at=self.clock.instant,
            events=(),
        )
        transition = self.preparer.prepare_frontier(
            command_id=command, checkpoint=previous.checkpoint, frontier=frontier
        )
        return self.prepare(transition, previous)


@pytest.fixture
def h(tmp_path):
    value = Harness(tmp_path)
    yield value
    value.engine.dispose()


def test_actual_engine_restart_preserves_exact_checkpoint_and_original_retry(h):
    first = h.publish(h.prepare())
    original = h.store.restore(h.scope)
    assert original.receipt == first and original.checkpoint == h.first.checkpoint
    h.publish(h.next(original))
    restarted = h.new_store()
    latest = restarted.restore(h.scope)
    assert latest.receipt.commit.sequence == 2 and latest.checkpoint.now > original.checkpoint.now
    retained_first = restarted.restore(h.scope, command_id="initialize")
    assert retained_first.checkpoint == h.first.checkpoint
    calls = h.composer.applied
    with restarted.write_transaction() as connection:
        retry = restarted.retry_in_transaction(
            connection,
            original=retained_first,
            command_sha256=h.first.command_sha256,
            fence=h.fence,
        )
    assert retry == first and h.composer.applied == calls
    assert (
        retained_first.checkpoint.remaining_wall_nanoseconds
        == h.first.checkpoint.remaining_wall_nanoseconds
    )


@pytest.mark.parametrize("kind", ["outer_rollback", "final_expiry", "source_changed"])
def test_failure_rolls_back_coupled_heads_journal_index_and_head(h, kind):
    prepared = h.prepare()
    with h.engine.connect() as connection:
        original = connection.scalar(sa.select(fixture_heads.c.payload))
    if kind == "final_expiry":
        h.composer.after_apply = lambda: h.clock.advance(timedelta(seconds=31))
    if kind == "source_changed":
        with _write_transaction(h.engine) as connection:
            connection.execute(sa.update(fixture_evidence).values(source_sha256="f" * 64))
    with (
        pytest.raises((ValueError, RuntimeError, AccountLeaseOwnershipLost)),
        h.store.write_transaction() as connection,
    ):
        h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)
        raise RuntimeError("outer owner declines commit")
    with h.engine.connect() as connection:
        assert connection.scalar(sa.select(fixture_heads.c.payload)) == original
        for table in (commits, heads, journal_entries):
            assert connection.scalar(sa.select(sa.func.count()).select_from(table)) == 0


@pytest.mark.parametrize("kind", ["prepared_copy", "engine_copy", "scope", "fake_heads"])
def test_owned_engine_and_composition_bindings_cannot_be_replaced(h, kind):
    if kind == "engine_copy":
        with pytest.raises(ValueError, match="OWNED"):
            h.prepare(replace(h.first))
    elif kind == "scope":
        with pytest.raises(ValueError, match="SCOPE"):
            h.store.prepare(
                h.first,
                scope=replace(h.scope, account_id="other"),
                previous=None,
                source_evidence=h.source,
            )
    else:
        prepared = h.prepare()
        if kind == "prepared_copy":
            with pytest.raises(ValueError, match="OWNED"):
                h.publish(replace(prepared))
        else:
            h.composer.apply_in_transaction = lambda *args, **kwargs: replace(
                prepared.composition.resulting_heads, ledger_sha256="f" * 64
            )
            with pytest.raises(ValueError, match="HEADS"):
                h.publish(prepared)


def test_actual_engine_decision_requires_explicit_supported_admission_composer(h):
    first = h.publish(h.prepare())
    previous = h.store.restore(h.scope)
    transition = h.preparer.prepare_frontier(
        command_id="decision",
        checkpoint=previous.checkpoint,
        frontier=project(previous.checkpoint, h.sources),
    )
    assert any(d.installed_commitments for d in transition.new_decisions)
    with pytest.raises(ValueError, match="UNSUPPORTED_HOLD_OR_ADMISSION"):
        h.prepare(transition, previous)
    assert h.store.restore(h.scope).receipt == first


@pytest.mark.parametrize("target", ["payload", "journal", "object", "source", "head", "orphan"])
def test_fresh_restore_detects_corruption_of_complete_closure(h, target):
    h.publish(h.prepare())
    assert h.store.restore(h.scope) is not None
    with _write_transaction(h.engine) as connection:
        if target == "payload":
            connection.execute(sa.update(commits).values(canonical_payload=b"invalid"))
        elif target == "journal":
            connection.execute(sa.update(journal_entries).values(payload=b"invalid"))
        elif target == "source":
            connection.execute(sa.update(fixture_evidence).values(source_sha256="f" * 64))
        elif target == "head":
            connection.execute(sa.update(heads).values(checkpoint_sha256="f" * 64))
        elif target == "orphan":
            connection.execute(sa.delete(heads))
    if target == "object":
        h.artifacts.read = lambda *args, **kwargs: b"wrong bounded bytes"
    with pytest.raises((ValueError, AssertionError)):
        h.store.restore(h.scope)


@pytest.mark.parametrize("column", ["command_id", "scope_sha256", "canonical_payload", "sequence"])
def test_corrupt_sqlite_storage_is_bounded_before_decode(h, column):
    h.publish(h.prepare())
    with _write_transaction(h.engine) as connection:
        connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
        if column == "command_id":
            # Keep lookup identity usable: corrupt another bounded text field.
            connection.execute(sa.update(commits).values(owner_id="x" * 1000000))
        elif column == "canonical_payload":
            connection.execute(sa.update(commits).values(canonical_payload=b"x" * 1000000))
        elif column == "sequence":
            connection.execute(sa.update(commits).values(sequence="x" * 1000000))
        else:
            connection.execute(sa.update(commits).values(scope_sha256="x" * 1000000))
    with _repeatable_read_transaction(h.engine) as connection:
        raw = h.store.capture_commit_in_transaction(
            connection, scope=h.scope, command_id="initialize"
        )
    assert all(not isinstance(v, (str, bytes)) or len(v) <= 16385 for v in raw.row.values())
    with pytest.raises(ValueError):
        h.store.resolve_index(raw)


def test_discovery_and_current_prefix_changes_are_rechecked(h):
    h.publish(h.prepare())
    with _repeatable_read_transaction(h.engine) as connection:
        row = h.store.capture_current_in_transaction(connection, scope=h.scope)
    index = h.store.resolve_index(row)
    with _write_transaction(h.engine) as connection:
        connection.execute(sa.update(commits).values(receipt_sha256="f" * 64))
    with (
        _repeatable_read_transaction(h.engine) as connection,
        pytest.raises(ValueError, match="DISCOVERY_CHANGED"),
    ):
        h.store.capture_snapshot_in_transaction(connection, index=index)


def test_detached_stalled_resolution_does_not_block_writer_commit(h):
    h.publish(h.prepare())
    reached, release = Event(), Event()
    h.composer.resolve_hook = lambda: (reached.set(), release.wait(5))
    with ThreadPoolExecutor(max_workers=1) as pool:
        reader = pool.submit(h.store.restore, h.scope)
        assert reached.wait(5)
        try:
            with _write_transaction(h.engine) as connection:
                connection.execute(sa.update(fixture_heads).values(payload=fixture_heads.c.payload))
        finally:
            release.set()
        assert reader.result(timeout=5) is not None


def test_same_prepared_append_race_has_one_publication_then_original_retry(h):
    prepared = h.prepare()
    barrier = Barrier(2)

    def run():
        barrier.wait()
        try:
            return h.publish(prepared)
        except ContinuousAccountConflict as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert sum(not isinstance(v, str) for v in results) == 1
    assert "CONTINUOUS_RESTORE_ORIGINAL_RETRY_REQUIRED" in results
    assert h.store.restore(h.scope).receipt.commit.sequence == 1


def test_sql_requires_physical_transaction_and_owned_resolved_values(h):
    h.publish(h.prepare())
    original = h.store.restore(h.scope)
    with h.engine.connect() as connection, pytest.raises(ValueError, match="TRANSACTION"):
        h.store.retry_in_transaction(
            connection, original=original, command_sha256=h.first.command_sha256, fence=h.fence
        )
    with h.store.write_transaction() as connection, pytest.raises(ValueError, match="OWNED"):
        h.store.retry_in_transaction(
            connection,
            original=replace(original),
            command_sha256=h.first.command_sha256,
            fence=h.fence,
        )


def test_no_codec_or_object_io_runs_inside_publication_transaction(h, monkeypatch):
    prepared = h.prepare()

    def forbidden(*args, **kwargs):
        raise AssertionError("detached work was invoked under SQL")

    monkeypatch.setattr(codec, "encode_record", forbidden)
    monkeypatch.setattr(codec, "decode_record", forbidden)
    monkeypatch.setattr(h.artifacts, "read", forbidden)
    monkeypatch.setattr(h.artifacts, "put", forbidden)
    receipt = h.publish(prepared)
    assert receipt.commit.sequence == 1


@pytest.mark.parametrize("change", ["owner", "payload", "timestamp"])
def test_exact_retained_lease_revision_is_part_of_fresh_restore(h, change):
    h.publish(h.prepare())
    assert h.store.restore(h.scope) is not None
    with _write_transaction(h.engine) as connection:
        connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
        if change == "owner":
            connection.execute(sa.update(phase2_account_leases).values(owner_id="other-owner"))
        elif change == "payload":
            connection.execute(
                sa.update(phase2_account_leases).values(canonical_payload="x" * 1000000)
            )
        else:
            connection.exec_driver_sql(
                "UPDATE phase2_account_leases SET acquired_at = ?", ("x" * 1000000,)
            )
    with pytest.raises(ValueError, match="LEASE_INVALID"):
        h.store.restore(h.scope)


def test_retry_with_changed_request_digest_never_applies_again(h):
    first = h.publish(h.prepare())
    original = h.store.restore(h.scope)
    with (
        h.store.write_transaction() as connection,
        pytest.raises(ValueError, match="IMMUTABLE_RETRY_CONFLICT"),
    ):
        h.store.retry_in_transaction(
            connection, original=original, command_sha256="f" * 64, fence=h.fence
        )
    assert h.composer.applied == 1 and h.store.restore(h.scope).receipt == first


@pytest.mark.parametrize("kind", ["read", "external_immediate", "other_store", "closed", "reused"])
def test_only_exact_registered_live_write_transaction_is_admitted(h, kind):
    prepared = h.prepare()
    if kind in ("read", "external_immediate"):
        with h.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN" if kind == "read" else "BEGIN IMMEDIATE")
            with pytest.raises(ValueError, match="OWNED_CONTINUOUS_WRITE_TRANSACTION"):
                h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)
            connection.rollback()
    elif kind == "other_store":
        with (
            h.new_store().write_transaction() as connection,
            pytest.raises(ValueError, match="OWNED_CONTINUOUS_WRITE_TRANSACTION"),
        ):
            h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)
    elif kind == "closed":
        with h.store.write_transaction() as connection:
            pass
        with pytest.raises(ValueError, match="TRANSACTION"):
            h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)
    else:
        with (
            pytest.raises(ValueError, match="OWNED_CONTINUOUS_WRITE_TRANSACTION"),
            h.store.write_transaction() as connection,
        ):
            connection.rollback()
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)
    assert not h.store._write_connections
    assert h.store.restore(h.scope) is None


@pytest.mark.parametrize("kind", ["prepared_metadata", "prepared_field", "resolved_metadata"])
def test_same_instance_mutation_is_rejected_without_codec_under_lock(h, kind):
    prepared = h.prepare()
    if kind == "resolved_metadata":
        h.publish(prepared)
        original = h.store.restore(h.scope)
        object.__setattr__(
            original.receipt, "recorded_at", original.receipt.recorded_at + timedelta(seconds=1)
        )
        with h.store.write_transaction() as connection, pytest.raises(ValueError, match="CHANGED"):
            h.store.retry_in_transaction(
                connection,
                original=original,
                command_sha256=h.first.command_sha256,
                fence=h.fence,
            )
    else:
        if kind == "prepared_metadata":
            object.__setattr__(prepared.commit.transition, "command_id", "tampered")
        else:
            object.__setattr__(prepared, "payload", b"tampered")
        with pytest.raises(ValueError, match="CHANGED"):
            h.publish(prepared)


def test_fixed_through_pages_exclude_later_appends_and_detect_missing_prefix(h):
    h.publish(h.prepare())
    first = h.store.restore(h.scope)
    h.publish(h.next(first, "second"))
    with _repeatable_read_transaction(h.engine) as connection:
        raw = h.store.capture_current_in_transaction(connection, scope=h.scope)
    through = h.store.resolve_index(raw)
    second = h.store.restore(h.scope)
    h.publish(h.next(second, "third"))
    previous = None
    for expected in (1, 2):
        with _repeatable_read_transaction(h.engine) as connection:
            page = h.store.capture_page_in_transaction(
                connection, through=through, after=previous, limit=1
            )
        assert len(page) == 1 and page[0].row["sequence"] == expected
        index = h.store.resolve_index(page[0], previous=previous)
        with _repeatable_read_transaction(h.engine) as connection:
            raw = h.store.capture_snapshot_in_transaction(connection, index=index)
        previous = h.store.resolve_snapshot(raw, previous=previous)
    assert previous.receipt == second.receipt
    with _write_transaction(h.engine) as connection:
        connection.execute(sa.delete(commits).where(commits.c.command_id == "second"))
    with pytest.raises(ValueError, match="PAGE_INCOMPLETE"):
        h.store.restore(h.scope)


@pytest.mark.parametrize("limit", [0, 65, True])
def test_page_request_bound_is_explicit(h, limit):
    h.publish(h.prepare())
    with _repeatable_read_transaction(h.engine) as connection:
        raw = h.store.capture_current_in_transaction(connection, scope=h.scope)
    through = h.store.resolve_index(raw)
    with (
        _repeatable_read_transaction(h.engine) as connection,
        pytest.raises(ValueError, match="PAGE_BOUND"),
    ):
        h.store.capture_page_in_transaction(connection, through=through, limit=limit)


def test_postgres_explicit_rr_atomic_restart_retry_and_rollback(postgres_engine, tmp_path):
    schema = "continuous_" + uuid4().hex
    with postgres_engine.begin() as connection:
        connection.execute(sa.schema.CreateSchema(schema))
    engine = postgres_engine.execution_options(schema_translate_map={None: schema})
    try:
        value = Harness(tmp_path, engine)
        first = value.publish(value.prepare())
        original = value.store.restore(value.scope)
        pending = value.next(original)
        with pytest.raises(RuntimeError), value.store.write_transaction() as connection:
            assert connection.get_isolation_level() == "REPEATABLE READ"
            value.store.commit_in_transaction(connection, prepared=pending, fence=value.fence)
            raise RuntimeError("owner rollback")
        assert value.store.restore(value.scope).receipt == first
        value.publish(pending)
        restarted = value.new_store()
        retained = restarted.restore(value.scope, command_id="initialize")
        with restarted.write_transaction() as connection:
            assert (
                restarted.retry_in_transaction(
                    connection,
                    original=retained,
                    command_sha256=value.first.command_sha256,
                    fence=value.fence,
                )
                == first
            )
    finally:
        with postgres_engine.begin() as connection:
            connection.execute(sa.schema.DropSchema(schema, cascade=True))


@pytest.mark.parametrize("wrapper", ["continuous", "coordinator"])
def test_deferred_parent_failure_removes_actual_b_children_and_coupled_rows(h, wrapper):
    from tests.integration.test_sql_daily_runtime_risk import (
        pending_fixture,
        prepare_attempt,
        prepare_parent_fixture,
    )

    daily, source, envelopes, preparations = pending_fixture(h.engine)
    before = daily.counts()
    prepared = prepare_attempt(daily, envelopes, preparations)
    context = (
        h.store.write_transaction
        if wrapper == "continuous"
        else lambda: _write_transaction(h.engine)
    )
    physical = None
    with pytest.raises(sa.exc.IntegrityError), context() as connection:
        physical = connection.connection.driver_connection
        daily.store.commit_attempt_prepared_in_transaction(
            connection, prepared, fence=daily.lease.fence
        )
        connection.execute(
            sa.insert(fixture_heads).values(account_id="coupled-rollback", payload=b"coupled")
        )
        assert daily.counts() == before  # Separate reader still sees the committed prefix.
    assert physical.in_transaction is False
    assert not h.store._write_connections
    assert daily.counts() == before
    with h.engine.connect() as connection:
        assert connection.connection.driver_connection.in_transaction is False
        assert (
            connection.scalar(
                sa.select(fixture_heads.c.payload).where(
                    fixture_heads.c.account_id == "coupled-rollback"
                )
            )
            is None
        )
    # Reuse the pool and same immutable preparation in an explicitly complete
    # relational parent fixture. Its bytes are not claimed as a real checkpoint.
    parent_journal, parent_append, parent_values = prepare_parent_fixture(daily, source)
    with context() as connection:
        daily.store.commit_attempt_prepared_in_transaction(
            connection, prepared, fence=daily.lease.fence
        )
        parent_journal.append_in_transaction(connection, parent_append)
        connection.execute(sa.insert(commits).values(**parent_values))
    assert daily.counts() == (
        *before[:5],
        before[5] + 1,
        before[6],
        before[7] + 1,
        before[8] + 1,
        before[9],
    )


def _deferred_tables(engine):
    local = sa.MetaData()
    parent = sa.Table("test_rollback_parent", local, sa.Column("id", sa.Integer, primary_key=True))
    child = sa.Table(
        "test_rollback_child",
        local,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("parent_id", sa.Integer, nullable=False),
        sa.ForeignKeyConstraint(
            ["parent_id"], [parent.c.id], deferrable=True, initially="DEFERRED"
        ),
    )
    coupled = sa.Table(
        "test_rollback_coupled", local, sa.Column("id", sa.Integer, primary_key=True)
    )
    local.create_all(engine)
    return parent, child, coupled


@pytest.mark.parametrize("wrapper", ["continuous", "coordinator"])
@pytest.mark.parametrize("body_failure", [False, True])
def test_outer_write_failure_cleans_pool_and_preserves_original_error(h, wrapper, body_failure):
    parent, child, coupled = _deferred_tables(h.engine)
    context = (
        h.store.write_transaction
        if wrapper == "continuous"
        else lambda: _write_transaction(h.engine)
    )
    error = RuntimeError("explicit-body-failure")
    with (
        pytest.raises(RuntimeError if body_failure else sa.exc.IntegrityError) as caught,
        context() as connection,
    ):
        physical = connection.connection.driver_connection
        connection.execute(sa.insert(child).values(id=1, parent_id=1))
        connection.execute(sa.insert(coupled).values(id=1))
        if body_failure:
            raise error
    if body_failure:
        assert caught.value is error
    assert not physical.in_transaction and not h.store._write_connections
    with h.engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(child)) == 0
        assert connection.scalar(sa.select(sa.func.count()).select_from(coupled)) == 0
    with context() as connection:
        connection.execute(sa.insert(parent).values(id=1))
        connection.execute(sa.insert(child).values(id=1, parent_id=1))
    with h.engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(child)) == 1


@pytest.mark.parametrize("wrapper", ["continuous", "coordinator"])
def test_rollback_failure_discards_physical_connection_and_keeps_commit_error(tmp_path, wrapper):
    import sqlite3

    class BrokenRollback(sqlite3.Connection):
        fail_next_rollback = False

        def rollback(self):
            if self.fail_next_rollback:
                self.fail_next_rollback = False
                raise sqlite3.OperationalError("explicit-cleanup-failure")
            return super().rollback()

    engine = sa.create_engine(
        f"sqlite+pysqlite:///{tmp_path}/cleanup.sqlite",
        connect_args={"factory": BrokenRollback},
        pool_size=1,
        max_overflow=0,
    )

    @sa.event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    owner = Harness(tmp_path, engine=engine)
    parent, child, _ = _deferred_tables(engine)
    context = (
        owner.store.write_transaction
        if wrapper == "continuous"
        else lambda: _write_transaction(engine)
    )
    try:
        with pytest.raises(sa.exc.IntegrityError) as caught, context() as connection:
            physical = connection.connection.driver_connection
            connection.execute(sa.insert(child).values(id=1, parent_id=1))
            physical.fail_next_rollback = True
        assert "FOREIGN KEY" in str(caught.value) and "explicit-cleanup-failure" not in str(
            caught.value
        )
        with engine.connect() as connection:
            assert connection.connection.driver_connection is not physical
            assert connection.scalar(sa.select(sa.func.count()).select_from(child)) == 0
        with context() as connection:
            connection.execute(sa.insert(parent).values(id=1))
            connection.execute(sa.insert(child).values(id=1, parent_id=1))
        assert not owner.store._write_connections
    finally:
        engine.dispose()


@pytest.mark.parametrize("wrapper", ["continuous", "coordinator"])
def test_postgres_deferred_commit_failure_rolls_back_coupled_rows(
    postgres_engine, tmp_path, wrapper
):
    schema = "continuous_deferred_" + uuid4().hex
    with postgres_engine.begin() as connection:
        connection.execute(sa.schema.CreateSchema(schema))
    engine = postgres_engine.execution_options(schema_translate_map={None: schema})
    try:
        owner = Harness(tmp_path, engine=engine)
        parent, child, coupled = _deferred_tables(engine)
        context = (
            owner.store.write_transaction
            if wrapper == "continuous"
            else lambda: _write_transaction(engine)
        )
        with pytest.raises(sa.exc.IntegrityError), context() as connection:
            connection.execute(sa.insert(child).values(id=1, parent_id=1))
            connection.execute(sa.insert(coupled).values(id=1))
        with engine.connect() as connection:
            assert connection.scalar(sa.select(sa.func.count()).select_from(child)) == 0
            assert connection.scalar(sa.select(sa.func.count()).select_from(coupled)) == 0
        with context() as connection:
            connection.execute(sa.insert(parent).values(id=1))
            connection.execute(sa.insert(child).values(id=1, parent_id=1))
    finally:
        with postgres_engine.begin() as connection:
            connection.execute(sa.schema.DropSchema(schema, cascade=True))


def test_owned_publication_readback_has_no_codec_and_expires_with_transaction(h, monkeypatch):
    prepared = h.prepare()
    with monkeypatch.context() as patch, h.store.write_transaction() as connection:
        receipt = h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)

        def blocked(*args, **kwargs):
            raise AssertionError("CODEC_OR_OBJECT_INSIDE_PUBLICATION_READBACK")

        patch.setattr(codec, "encode_record", blocked)
        patch.setattr(codec, "decode_record", blocked)
        patch.setattr(h.artifacts, "read", blocked)
        result = h.store.require_committed_in_transaction(
            connection, prepared=prepared, receipt=receipt
        )
        assert result.row["commit_sha256"] == receipt.commit.semantic_sha256
        with pytest.raises(ValueError, match="PUBLICATION_REQUIRED"):
            h.store.require_committed_in_transaction(
                connection, prepared=prepared, receipt=replace(receipt)
            )
        with pytest.raises(ValueError, match="OWNED"):
            h.store.require_committed_in_transaction(
                connection, prepared=replace(prepared), receipt=receipt
            )
        # Actual outer COMMIT runs before the monkeypatch context exits.
    assert not h.store._pending_publications
    with (
        h.store.write_transaction() as other,
        pytest.raises(ValueError, match="PUBLICATION_REQUIRED"),
    ):
        h.store.require_committed_in_transaction(other, prepared=prepared, receipt=receipt)
    with pytest.raises(ValueError):
        h.store.require_committed_in_transaction(connection, prepared=prepared, receipt=receipt)


@pytest.mark.parametrize("changed", ["index", "head", "journal", "lease", "receipt"])
def test_outer_owner_rejects_changed_issued_publication_and_rolls_back(h, changed):
    prepared = h.prepare()
    with pytest.raises(ValueError), h.store.write_transaction() as connection:
        receipt = h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)
        h.store.require_committed_in_transaction(connection, prepared=prepared, receipt=receipt)
        if changed == "index":
            connection.execute(sa.update(commits).values(checkpoint_sha256="f" * 64))
        elif changed == "head":
            connection.execute(sa.update(heads).values(commit_sha256="f" * 64))
        elif changed == "journal":
            connection.execute(sa.update(journal_entries).values(payload=b"{}"))
        elif changed == "lease":
            connection.execute(sa.update(phase2_account_leases).values(owner_id="changed"))
        else:
            object.__setattr__(receipt, "recorded_at", receipt.recorded_at + timedelta(seconds=1))
    assert not h.store._pending_publications
    with h.engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(commits)) == 0
        assert connection.scalar(sa.select(sa.func.count()).select_from(journal_entries)) == 0


def test_outer_owner_checks_actual_lease_after_successful_c_publication(h):
    prepared = h.prepare()
    with pytest.raises(AccountLeaseOwnershipLost), h.store.write_transaction() as connection:
        receipt = h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)
        h.store.require_committed_in_transaction(connection, prepared=prepared, receipt=receipt)
        assert connection.scalar(sa.select(sa.func.count()).select_from(commits)) == 1
        h.clock.instant = receipt.fence_reference.valid_until
    assert not h.store._pending_publications
    with h.engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(commits)) == 0
        assert connection.scalar(sa.select(sa.func.count()).select_from(journal_entries)) == 0


def test_body_exception_after_c_publication_is_preserved_and_clears_pending(h):
    prepared = h.prepare()
    failure = RuntimeError("FIXTURE_OWNER_BODY_FAILED")
    with pytest.raises(RuntimeError) as raised, h.store.write_transaction() as connection:
        h.store.commit_in_transaction(connection, prepared=prepared, fence=h.fence)
        raise failure
    assert raised.value is failure and not h.store._pending_publications
    with h.engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(commits)) == 0
    assert h.publish(prepared).commit.sequence == 1


def test_public_resolved_guard_requires_exact_original_store_value(h, monkeypatch):
    h.publish(h.prepare())
    resolved = h.store.restore(h.scope)

    def blocked(*args, **kwargs):
        raise AssertionError("NO_NEW_IO_OR_DECODE_IN_OWNERSHIP_GUARD")

    with monkeypatch.context() as patch:
        patch.setattr(h.engine, "connect", blocked)
        patch.setattr(codec, "decode_record", blocked)
        patch.setattr(h.artifacts, "read", blocked)
        h.store.require_resolved(resolved)
        with pytest.raises(ValueError, match="OWNED"):
            h.store.require_resolved(replace(resolved))
        with pytest.raises(ValueError, match="OWNED"):
            h.new_store().require_resolved(resolved)
