"""Actual SQL/lease fixtures; retained synthetic producers are not production authentication."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
from threading import Barrier
from uuid import uuid4

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.application.daily_commitment_install import prepare_daily_commitments
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.account_coordinator import AccountLeaseOwnershipLost, AccountLeasePolicy
from packages.domain.daily_risk import evaluate_daily_risk
from packages.domain.daily_runtime_contracts import RuntimeProducerMap
from packages.domain.daily_runtime_risk import (
    build_daily_runtime_evidence,
    runtime_source_value_sha256,
)
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalEntry,
    JournalKey,
    JournalReceipt,
    JournalRecord,
    empty_head,
)
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlIncidentDisposition,
    OperationalControlState,
    _operational_control_rearm_evidence,
)
from packages.domain.personal_contracts import content_digest
from packages.domain.portfolio import daily_target_to_intents
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.account_coordinator import (
    _write_transaction as _original_write,
)
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.daily_runtime_risk import (
    DailyRuntimeRiskConflict,
    ResolvedRuntimeRiskInputs,
    RuntimeAssignmentCommand,
    RuntimeProducerRawSnapshot,
    SqlDailyRuntimeRisk,
    VerifiedRuntimeAssignmentCommand,
    capture_runtime_table,
)
from packages.persistence.daily_runtime_risk_schema import (
    DAILY_RUNTIME_TABLES,
    daily_runtime_hold_events,
    daily_runtime_hold_heads,
)
from packages.persistence.database import create_database_engine
from packages.persistence.operational_control import (
    SqlOperationalControlRepository,
)
from packages.persistence.schema import metadata
from tests.integration.test_phase2_postgres_exit import postgres_engine as postgres_engine
from tests.integration.test_sql_account_coordinator import MutableClock
from tests.unit.test_daily_commitment_install import install_case
from tests.unit.test_daily_risk_snapshot import END, START, runtime_case
from tests.unit.test_daily_target_conversion import NOW, PIN, SHA, D

fixture_meta = sa.MetaData()
records = sa.Table(
    "test_daily_runtime_records",
    fixture_meta,
    sa.Column("account_id", sa.String(128), primary_key=True),
    sa.Column("name", sa.String(128), primary_key=True),
    sa.Column("digest", sa.String(64), nullable=False),
    sa.Column("payload", sa.LargeBinary, nullable=False),
)


def retain(connection, account, name, value):
    payload = codec.encode_record(value)
    connection.execute(
        sa.insert(records).values(
            account_id=account, name=name, digest=sha256(payload).hexdigest(), payload=payload
        )
    )


@contextmanager
def _write_transaction(engine):
    if engine.dialect.name == "postgresql":
        with (
            engine.connect().execution_options(isolation_level="REPEATABLE READ") as connection,
            connection.begin(),
        ):
            yield connection
    else:
        with _original_write(engine) as connection:
            yield connection


def read(snapshot, account, name, cls):
    row = next(
        row
        for table in snapshot.tables
        for row in table.rows
        if row["account_id"] == account and row["name"] == name
    )
    assert sha256(row["payload"]).hexdigest() == row["digest"]
    value = codec.decode_record(row["payload"], cls)
    assert codec.encode_record(value) == row["payload"]
    return value


class RetainedFixtureReader:
    """Required reader backed by typed rows, explicit test command and real control heads."""

    def __init__(self, account):
        self.account = account
        self.reads = 0

    def capture_in_transaction(self, connection, *, account_id, refs, owner_command_ref, budget):
        assert account_id == self.account
        return RuntimeProducerRawSnapshot(
            (capture_runtime_table(connection, records, account_id=account_id, budget=budget),)
        )

    def resolve(
        self, snapshot, *, assignment, previous, refs, owner_command_ref, fence_receipt, control
    ):
        if refs is not None:
            self.reads += 1
            value = read(
                snapshot,
                self.account,
                "resolved-" + refs.semantic_sha256,
                ResolvedRuntimeRiskInputs,
            )
            assert value.inputs == refs and refs.assignment_sha256 == assignment.semantic_sha256
            assert fence_receipt.fence.account_id == self.account
            for source in refs.sources:
                assert read(snapshot, self.account, source.semantic_sha256, type(source)) == source
            return value
        value = read(
            snapshot,
            self.account,
            "command-" + owner_command_ref.command_id,
            VerifiedRuntimeAssignmentCommand,
        )
        assert (
            read(snapshot, self.account, "receipt-" + owner_command_ref.command_id, JournalReceipt)
            == owner_command_ref
        )
        assert value.command.owner_id == "explicit-fixture-owner"
        assert value.command.before_assignment_sha256 == (
            None if previous is None else previous.semantic_sha256
        )
        assert value.command.after_assignment_sha256 == assignment.semantic_sha256
        assert (
            read(snapshot, self.account, "quiescence-" + owner_command_ref.command_id, str)
            == value.command.quiescence_sha256
        )
        heads = replace(
            value.current_heads,
            control_revision=0 if control is None else control.sequence_number,
            lease_generation=fence_receipt.fence.fencing_generation,
        )
        return replace(value, current_heads=heads)

    def recheck_in_transaction(self, connection, snapshot):
        # The store compares every captured byte as well; this reader independently pins its scope.
        assert len(snapshot.tables) == 1 and snapshot.tables[0].table is records
        assert connection.scalar(
            sa.select(sa.func.count())
            .select_from(records)
            .where(records.c.account_id == self.account)
        ) == len(snapshot.tables[0].rows)


class Harness:
    def __init__(self, engine, account=None, *, two=False, decision_at=NOW, observed=False):
        self.decision_at = decision_at
        self.engine = engine
        self.account = account or "daily-" + uuid4().hex
        metadata.create_all(engine)
        fixture_meta.create_all(engine)
        self.clock = MutableClock(self.decision_at)
        self.coordinator = SqlAccountCoordinator(
            account_id=self.account,
            authority=SqlAccountCoordinatorAuthority(
                engine=engine,
                policy=AccountLeasePolicy(
                    "fixture",
                    "1",
                    timedelta(seconds=60),
                    timedelta(seconds=5),
                    timedelta(seconds=10),
                ),
                clock=self.clock,
            ),
        )
        self.lease = self.coordinator.acquire("owner")
        self.reader = RetainedFixtureReader(self.account)
        self.store = SqlDailyRuntimeRisk(
            engine,
            coordinator=self.coordinator,
            codec=codec,
            producers=self.reader,
            accounting=PersonalAccounting(),
        )
        self.controls = SqlOperationalControlRepository(engine=engine, clock=self.clock)
        self.control = self.controls.apply(
            self.command(
                OperationalControlCommandKind.INITIALIZE_HALTED,
                "initial-control",
                OperationalControlState.HALTED,
            )
        )
        self.case = install_case(two=two)
        if observed:
            from packages.domain.accounting_contracts import AccountingCommand, AccountingState

            policy = replace(
                self.case["execution_policy"],
                model_id="observed-facts-v1",
                settlement_model="observed-only-v1",
                correction_settlement="explicit-only-v1",
                terminal_model="observed-only-v1",
            )
            state = AccountingState("account")
            context = self.case["context"]
            for index, payload in enumerate(
                (*self.case["state"].cash_flows, *self.case["state"].marks), 1
            ):
                context = replace(
                    context, point=replace(context.point, reduction_sequence=index, stage=2)
                )
                transition = PersonalAccounting().advance(
                    state=state,
                    context=context,
                    policy=policy,
                    command=AccountingCommand("observed-bootstrap-" + str(index), payload),
                )
                assert transition.disposition == "applied", transition.reasons
                state = transition.state
            self.case.update(
                state=state,
                execution_policy=policy,
                context=replace(
                    context, point=replace(context.point, reduction_sequence=index + 1, stage=5)
                ),
            )
        self.case["context"] = replace(
            self.case["context"],
            economic_at=self.decision_at,
            point=replace(self.case["context"].point, knowledge_at=self.decision_at),
        )
        self.case["batch"] = replace(
            self.case["batch"],
            target=replace(
                self.case["batch"].target,
                trigger=replace(self.case["batch"].target.trigger, as_of=self.decision_at),
            ),
        )
        self.state = replace(self.case["state"], account_id=self.account)
        self.snapshot = (
            PersonalAccounting()
            .project(
                state=self.state, context=self.case["context"], policy=self.case["execution_policy"]
            )
            .snapshot
        )
        self.batch = daily_target_to_intents(
            replace(self.case["batch"].target, not_before=START, expires_at=END),
            self.snapshot,
            strategy_pin=PIN,
        )
        base = runtime_case(snapshot=self.snapshot, batch=self.batch, now=self.decision_at)
        self.producer_map = RuntimeProducerMap(
            producers=tuple(replace(p, account_scope=self.account) for p in base[4].producers)
        )
        self.assignment = replace(
            base[0],
            account_id=self.account,
            producer_map_sha256=self.producer_map.semantic_sha256,
            enabled_for_new_exposure=False,
            instrument_symbols=self.case["context"].instruments,
        )
        self.base = base
        self.install(self.assignment)

    def command(self, kind, key, state, proof=None):
        actor = OperationalControlActor(
            "system"
            if kind == OperationalControlCommandKind.INITIALIZE_HALTED
            else "explicit-fixture-owner",
            OperationalControlActorKind.SYSTEM
            if kind == OperationalControlCommandKind.INITIALIZE_HALTED
            else OperationalControlActorKind.HUMAN,
            SHA,
            None if kind == OperationalControlCommandKind.INITIALIZE_HALTED else self.decision_at,
        )
        return OperationalControlCommand(
            self.account,
            key,
            kind,
            state,
            actor,
            "fixture-explicit-command",
            SHA,
            self.decision_at,
            rearm_evidence_sha256=proof,
        )

    def current(self, assignment=None):
        assignment = self.assignment if assignment is None else assignment
        original = self.base[3]
        heads = replace(
            original.heads,
            control_revision=self.control.sequence_number,
            lease_generation=self.lease.fencing_generation,
        )
        reconciliation = replace(
            original.reconciliation,
            heads=heads,
            scope=replace(original.reconciliation.scope, account_id=self.account),
        )
        return replace(
            original,
            snapshot_sha256=self.snapshot.semantic_sha256,
            assignment_sha256=assignment.semantic_sha256,
            heads=heads,
            reconciliation=reconciliation,
        )

    def install(self, assignment):
        refs = self.current(assignment)
        command_id = "assignment-" + str(assignment.generation)
        command = RuntimeAssignmentCommand(
            command_id,
            "explicit-fixture-owner",
            self.account,
            assignment.previous_assignment_sha256,
            assignment.semantic_sha256,
            refs.heads,
            content_digest(("fixture-quiesced/1", self.account, refs.heads)),
            self.decision_at,
            self.decision_at + timedelta(seconds=30),
        )
        verified = VerifiedRuntimeAssignmentCommand(command, refs.heads, refs.reconciliation)
        key = JournalKey("coordinator", self.account, self.account, "fixture", "synthetic", SHA)
        payload = codec.encode_record(command)
        record = JournalRecord(command_id, "fixture-owner-command/1", payload)
        append = JournalAppend(command_id, command.semantic_sha256, empty_head(key), (record,))
        entry = JournalEntry(
            key.semantic_sha256, 1, command_id, record, empty_head(key).entry_sha256
        )
        receipt = JournalReceipt(
            command_id,
            command.semantic_sha256,
            append.semantic_sha256,
            empty_head(key),
            entry.head,
            (command_id,),
            (sha256(payload).hexdigest(),),
        )
        with _write_transaction(self.engine) as connection:
            retain(connection, self.account, "command-" + command_id, verified)
            retain(connection, self.account, "receipt-" + command_id, receipt)
            retain(connection, self.account, "quiescence-" + command_id, command.quiescence_sha256)
        prepared = self.prepare_assignment(assignment, receipt)
        with _write_transaction(self.engine) as connection:
            self.store.install_prepared_in_transaction(connection, prepared, fence=self.lease.fence)
        self.assignment = assignment
        self.last_owner_receipt = receipt

    def enable(self):
        self.install(
            replace(
                self.assignment,
                generation=2,
                previous_assignment_sha256=self.assignment.semantic_sha256,
                enabled_for_new_exposure=True,
            )
        )
        # Explicit test verifier creates a head-bound proof and uses the public SQL re-arm API.
        initial = self.control
        human = OperationalControlActor(
            "explicit-fixture-owner", OperationalControlActorKind.HUMAN, SHA, self.decision_at
        )
        proof = _operational_control_rearm_evidence(
            scope_id=self.account,
            current_transition_id=initial.transition_id,
            current_transition_sha256=initial.semantic_sha256,
            current_state=initial.effective_state,
            current_state_epoch_id=initial.state_epoch_id,
            actor=human,
            checked_at=self.decision_at,
            expires_at=self.decision_at + timedelta(seconds=30),
            readiness_sha256=SHA,
            reconciliation_sha256=self.current().reconciliation.semantic_sha256,
            incident_register_sha256=SHA,
            reconciliation_clean=True,
            data_healthy=True,
            clock_healthy=True,
            working_order_ids=(),
            unknown_order_ids=(),
            pending_cancel_order_ids=(),
            incident_dispositions=tuple(
                sorted(
                    (
                        OperationalControlIncidentDisposition(
                            e.event_id, e.semantic_sha256, "fixture-reviewed", SHA, self.decision_at
                        )
                        for e in initial.blocking_events
                    ),
                    key=lambda d: d.event_id,
                )
            ),
        )
        self.control = self.controls.apply_authenticated_rearm(
            self.command(
                OperationalControlCommandKind.REARM,
                "explicit-rearm",
                OperationalControlState.RUNNING,
                proof.semantic_sha256,
            ),
            proof,
        )

    def request(self):
        refs = self.current()
        sources = tuple(
            replace(
                s,
                spec=self.producer_map.producers[index],
                account_id=self.account,
                status="blocked"
                if s.spec.role == "controls"
                and self.control.effective_state != OperationalControlState.RUNNING
                else "available",
                reasons=("FIXTURE_CONTROL_BLOCKED",)
                if s.spec.role == "controls"
                and self.control.effective_state != OperationalControlState.RUNNING
                else (),
                value_sha256=runtime_source_value_sha256(
                    s.spec.role, self.snapshot, self.batch, refs
                ),
            )
            for index, s in enumerate(refs.sources)
        )
        # Decision omits quotes, so map by exact role rather than positional offset.
        by_role = {p.role: p for p in self.producer_map.producers}
        sources = tuple(
            replace(s, spec=by_role[old.spec.role])
            for s, old in zip(sources, refs.sources, strict=True)
        )
        refs = replace(refs, sources=sources)
        resolved = ResolvedRuntimeRiskInputs(
            self.state,
            self.snapshot,
            refs,
            self.producer_map,
            self.case["context"],
            self.case["execution_policy"],
        )
        fact = build_daily_runtime_evidence(
            self.assignment,
            self.snapshot,
            self.batch,
            refs,
            producer_map=self.producer_map,
            evaluated_at=self.decision_at,
        )
        decision = evaluate_daily_risk(
            self.assignment.policy, self.snapshot, self.batch, fact, self.decision_at
        )
        commitments = (
            prepare_daily_commitments(
                state=self.state,
                snapshot=self.snapshot,
                batch=self.batch,
                decision=decision,
                context=resolved.context,
                execution_policy=resolved.execution_policy,
                risk_policy=self.assignment.policy,
                accounting=PersonalAccounting(),
                attempt_namespace="daily-runtime-attempt",
            ).commitments
            if decision.approved
            else ()
        )
        with _write_transaction(self.engine) as connection:
            retain(connection, self.account, "resolved-" + refs.semantic_sha256, resolved)
            for source in refs.sources:
                retain(connection, self.account, source.semantic_sha256, source)
        return dict(
            command_id="decision-1",
            request_sha256=SHA,
            batch=self.batch,
            assignment_sha256=self.assignment.semantic_sha256,
            input_refs=refs,
            prepared_commitments=commitments,
            fence=self.lease.fence,
        )

    def resolved(self, **selection):
        return self.store.resolve_snapshot(
            self.store.read_snapshot(account_id=self.account, fence=self.lease.fence, **selection)
        )

    def prepare_assignment(self, assignment, receipt):
        snapshot = self.resolved(owner_command_ref=receipt)
        return self.store.prepare_assignment(
            snapshot,
            assignment=assignment,
            expected_previous_sha256=assignment.previous_assignment_sha256,
            owner_command_ref=receipt,
        )

    def prepare(self, request):
        snapshot = self.resolved(command_id=request["command_id"], input_refs=request["input_refs"])
        return self.store.prepare_admission(
            snapshot, **{key: value for key, value in request.items() if key != "fence"}
        )

    def admit(self, request):
        prepared = self.prepare(request)
        with _write_transaction(self.engine) as connection:
            return self.store.admit_prepared_in_transaction(
                connection, prepared, fence=request["fence"]
            )

    def counts(self):
        with self.engine.connect() as connection:
            return tuple(
                connection.scalar(
                    sa.select(sa.func.count()).select_from(t).where(t.c.account_id == self.account)
                )
                for t in DAILY_RUNTIME_TABLES
            )


@pytest.fixture
def harness(tmp_path):
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'daily.sqlite'}")
    try:
        yield Harness(engine)
    finally:
        engine.dispose()


def test_first_assignment_disabled_then_explicit_enable_and_atomic_actual_prepared_holds(harness):
    assert not harness.assignment.enabled_for_new_exposure
    harness.enable()
    request = harness.request()
    admission = harness.admit(request)
    assert admission.decision.approved, admission.decision.reasons
    assert admission.live_authorized is False
    assert harness.counts() == (2, 1, 1, 1, 1, 0, 1, 0, 0, 0)
    snapshot = harness.resolved()
    inventory = snapshot.obligations
    loaded = snapshot.admissions[0].admission
    assert loaded == admission
    assert tuple(b.commitment for b in inventory.bindings) == request["prepared_commitments"]
    assert inventory.bindings[0].original_policy_sha256 == harness.assignment.policy.semantic_sha256


def test_disabled_rejection_is_durable_and_retry_does_not_reload_sources_or_refresh_time(harness):
    request = harness.request()
    first = harness.admit(request)
    assert not first.decision.approved and "RUNTIME_ASSIGNMENT_DISABLED" in first.decision.reasons
    before = harness.counts()
    harness.clock.advance(timedelta(seconds=1))
    reads = harness.reader.reads
    assert harness.admit(request) == first
    assert harness.reader.reads == reads and harness.counts() == before
    assert before == (1, 1, 1, 0, 0, 0, 0, 0, 0, 0)


def test_identical_approved_retry_and_conflicting_request_preserve_all_rows(harness):
    harness.enable()
    request = harness.request()
    first = harness.admit(request)
    before = harness.counts()
    assert harness.admit(request) == first
    with pytest.raises(DailyRuntimeRiskConflict, match="retry conflicts"):
        harness.admit({**request, "request_sha256": "b" * 64})
    assert harness.counts() == before


def test_wrong_prepared_commitment_rejects_entire_admission(harness):
    harness.enable()
    request = harness.request()
    before = harness.counts()
    wrong = replace(request["prepared_commitments"][0], created_sequence=999)
    with pytest.raises(DailyRuntimeRiskConflict, match="prospective"):
        harness.admit({**request, "prepared_commitments": (wrong,)})
    assert harness.counts() == before


@pytest.mark.parametrize(
    "failed_table",
    [
        "daily_runtime_admissions",
        "daily_runtime_hold_events",
        "daily_runtime_hold_heads",
        "daily_runtime_outbound",
    ],
)
def test_late_sql_failure_rolls_back_all_row_groups_even_if_caller_catches(harness, failed_table):
    harness.enable()
    request = harness.request()
    before = harness.counts()

    def fail(connection, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO " + failed_table):
            raise RuntimeError("controlled SQL failure")

    prepared = harness.prepare(request)
    sa.event.listen(harness.engine, "before_cursor_execute", fail)
    try:
        with (
            _write_transaction(harness.engine) as connection,
            pytest.raises(RuntimeError, match="controlled SQL failure"),
        ):
            harness.store.admit_prepared_in_transaction(
                connection, prepared, fence=request["fence"]
            )
    finally:
        sa.event.remove(harness.engine, "before_cursor_execute", fail)
    assert harness.counts() == before


def test_outer_transaction_rollback_and_source_tamper_leave_no_admission(harness):
    harness.enable()
    request = harness.request()
    before = harness.counts()
    prepared = harness.prepare(request)
    with pytest.raises(RuntimeError), _write_transaction(harness.engine) as connection:
        harness.store.admit_prepared_in_transaction(connection, prepared, fence=request["fence"])
        raise RuntimeError("parent failed")
    assert harness.counts() == before
    with harness.engine.begin() as connection:
        connection.execute(
            sa.update(records)
            .where(records.c.account_id == harness.account, records.c.name.like("resolved-%"))
            .values(payload=b"invalid")
        )
    with pytest.raises(AssertionError):
        harness.admit(request)
    assert harness.counts() == before


def test_replayed_enable_after_control_change_and_stale_fence_cannot_change_assignment(harness):
    harness.enable()
    before = harness.counts()
    with pytest.raises(DailyRuntimeRiskConflict, match="current heads changed"):
        harness.prepare_assignment(harness.assignment, harness.last_owner_receipt)
    request = harness.request()
    harness.clock.advance(timedelta(seconds=60))
    with pytest.raises(AccountLeaseOwnershipLost):
        harness.admit(request)
    assert harness.counts() == before


def test_missing_hold_head_or_modified_hold_cannot_disappear_from_inventory(harness):
    harness.enable()
    request = harness.request()
    harness.admit(request)
    with pytest.raises(sa.exc.IntegrityError), harness.engine.begin() as connection:
        connection.execute(
            sa.delete(daily_runtime_hold_heads).where(
                daily_runtime_hold_heads.c.account_id == harness.account
            )
        )
    with harness.engine.begin() as connection:
        connection.execute(
            sa.update(daily_runtime_hold_events)
            .where(daily_runtime_hold_events.c.account_id == harness.account)
            .values(payload=b"tampered")
        )
    with pytest.raises(DailyRuntimeRiskConflict, match="hold/outbound inventory"):
        harness.resolved()


def contend(harness, *, identical):
    harness.enable()
    request = harness.request()
    barrier = Barrier(2)

    def worker(number):
        selected = request if identical else {**request, "command_id": "decision-" + str(number)}
        prepared = harness.prepare(selected)
        barrier.wait(timeout=10)
        try:
            with _write_transaction(harness.engine) as connection:
                return harness.store.admit_prepared_in_transaction(
                    connection, prepared, fence=harness.lease.fence
                )
        except (DailyRuntimeRiskConflict, sa.exc.OperationalError):
            return harness.admit(selected) if identical else None

    with ThreadPoolExecutor(max_workers=2) as pool:
        return tuple(pool.map(worker, (1, 2)))


def test_two_actual_sqlite_connections_cannot_overallocate_or_duplicate(harness):
    first, second = contend(harness, identical=True)
    assert first == second and first.decision.approved
    assert harness.counts()[2:] == (1, 1, 1, 0, 1, 0, 0, 0)


@pytest.fixture
def pg_harness(postgres_engine):
    value = Harness(postgres_engine)
    yield value
    with postgres_engine.begin() as connection:
        for table in reversed(DAILY_RUNTIME_TABLES):
            connection.execute(sa.delete(table).where(table.c.account_id == value.account))
        connection.execute(sa.delete(records).where(records.c.account_id == value.account))
    # Existing fixture owns schema; account-scoped historical rows remain isolated by UUID.


def test_postgres_same_account_competing_capacity_has_one_winner(pg_harness):
    results = contend(pg_harness, identical=False)
    assert sum(value is not None for value in results) == 1
    assert pg_harness.counts()[2:] == (1, 1, 1, 0, 1, 0, 0, 0)


def test_postgres_identical_retry_returns_original_admission(pg_harness):
    first, second = contend(pg_harness, identical=True)
    assert first == second and first.decision.approved
    assert pg_harness.counts()[2:] == (1, 1, 1, 0, 1, 0, 0, 0)


def test_actual_nonempty_legacy_capacity_is_preserved_and_blocks_missing_bridge(tmp_path):
    from packages.persistence.schema import phase2_batch_reservations
    from tests.integration.test_phase2_batch_risk_persistence import _coordinator, _repository
    from tests.unit.test_batch_risk import EVALUATED_AT, mixed_case
    from tests.unit.test_batch_risk import MutableClock as LegacyClock

    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'legacy.sqlite'}")
    try:
        metadata.create_all(engine)
        _, desired, batch, capacity = mixed_case()
        clock = LegacyClock(EVALUATED_AT)
        coordinator = _coordinator(engine, clock=clock, account_id=capacity.account_id)
        lease = coordinator.acquire("legacy-owner")
        legacy = _repository(engine, capacity, coordinator, clock)
        decision = legacy.authorize(batch, desired, lease.fence)
        store = SqlDailyRuntimeRisk(
            engine,
            coordinator=coordinator,
            codec=codec,
            producers=RetainedFixtureReader(capacity.account_id),
            accounting=PersonalAccounting(),
        )
        with engine.connect() as connection:
            before = tuple(connection.execute(sa.select(phase2_batch_reservations)))
        with pytest.raises(DailyRuntimeRiskConflict, match="any legacy reservation history"):
            store.read_snapshot(account_id=capacity.account_id, fence=lease.fence)
        with engine.connect() as connection:
            assert tuple(connection.execute(sa.select(phase2_batch_reservations))) == before
        assert legacy.get_batch(decision.decision_id) == decision
    finally:
        engine.dispose()


def test_source_snapshot_expiring_during_transaction_rolls_back(harness):
    harness.enable()
    request = harness.request()
    before = harness.counts()
    original = harness.reader.resolve

    def delayed(snapshot, **kwargs):
        value = original(snapshot, **kwargs)
        harness.clock.advance(timedelta(seconds=5))
        return value

    harness.reader.resolve = delayed
    with pytest.raises(DailyRuntimeRiskConflict, match="expired before commit"):
        harness.admit(request)
    assert harness.counts() == before


def test_policy_cutover_preserves_exact_existing_hold_and_original_policy(harness):
    harness.enable()
    request = harness.request()
    admission = harness.admit(request)
    obligations = harness.resolved().obligations
    before = harness.counts()
    original = harness.assignment
    # A separately retained quiesced comparison covers the full existing inventory.
    refs = replace(
        harness.base[3],
        obligations=obligations,
        heads=replace(
            harness.base[3].heads, capacity_sha256=obligations.semantic_sha256, effect_watermark=1
        ),
    )
    harness.base = (*harness.base[:3], refs, *harness.base[4:])
    tightened = replace(
        original,
        generation=3,
        previous_assignment_sha256=original.semantic_sha256,
        policy=replace(original.policy, max_order_quantity=D(100)),
    )
    harness.install(tightened)
    snapshot = harness.resolved()
    assert snapshot.obligations == obligations
    assert snapshot.admissions[0].admission == admission
    assert harness.counts()[2:] == before[2:]
    assert obligations.bindings[0].original_policy_sha256 == original.policy.semantic_sha256
    assert tightened.policy.semantic_sha256 != original.policy.semantic_sha256


def test_second_member_failure_rolls_back_entire_two_intent_batch(harness):
    value = Harness(harness.engine, two=True)
    value.enable()
    request = value.request()
    assert len(request["prepared_commitments"]) == 2
    before = value.counts()
    inserts = 0

    def fail(connection, cursor, statement, parameters, context, many):
        nonlocal inserts
        if statement.startswith("INSERT INTO daily_runtime_hold_events"):
            inserts += 1
            if inserts == 2:
                raise RuntimeError("second member failed")

    sa.event.listen(value.engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(RuntimeError, match="second member failed"):
            value.admit(request)
    finally:
        sa.event.remove(value.engine, "before_cursor_execute", fail)
    assert value.counts() == before
    assert value.admit(request).decision.approved
    assert value.counts()[2:] == (1, 2, 2, 0, 2, 0, 0, 0)


def test_retry_rejects_different_explicit_input_refs_even_with_same_request_label(harness):
    request = harness.request()
    first = harness.admit(request)
    with pytest.raises(DailyRuntimeRiskConflict, match="retry conflicts"):
        harness.admit(
            {**request, "input_refs": replace(request["input_refs"], daily_return=D("-.01"))}
        )
    assert harness.admit(request) == first


def test_pending_outbound_or_owner_command_tamper_cannot_hide_on_read(harness):
    from packages.persistence.daily_runtime_risk_schema import (
        daily_runtime_assignments,
        daily_runtime_outbound,
    )

    harness.enable()
    request = harness.request()
    harness.admit(request)
    with harness.engine.begin() as connection:
        connection.execute(
            sa.update(daily_runtime_outbound)
            .where(daily_runtime_outbound.c.account_id == harness.account)
            .values(binding_sha256="b" * 64)
        )
    with pytest.raises(DailyRuntimeRiskConflict, match="hold/outbound inventory"):
        harness.resolved()
    with harness.engine.begin() as connection:
        connection.execute(
            sa.update(daily_runtime_assignments)
            .where(daily_runtime_assignments.c.account_id == harness.account)
            .values(command_sha256="b" * 64)
        )
    with pytest.raises(DailyRuntimeRiskConflict, match="owner command binding"):
        harness.resolved()


def test_required_producer_port_has_no_default_passing_implementation(harness):
    with pytest.raises(ValueError, match="complete integration ports"):
        SqlDailyRuntimeRisk(
            harness.engine,
            coordinator=harness.coordinator,
            codec=codec,
            producers=None,
            accounting=PersonalAccounting(),
        )


def test_owner_command_expiring_after_assignment_insert_rolls_back(harness):
    before = harness.counts()

    def elapsed(connection, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO daily_runtime_assignments"):
            harness.clock.advance(timedelta(seconds=30))

    sa.event.listen(harness.engine, "after_cursor_execute", elapsed)
    try:
        with pytest.raises(DailyRuntimeRiskConflict, match="evidence expired before commit"):
            harness.enable()
    finally:
        sa.event.remove(harness.engine, "after_cursor_execute", elapsed)
    assert harness.counts() == before
    assert harness.resolved().assignment == harness.assignment


def test_postgres_late_outbound_failure_rolls_back_all_row_groups(pg_harness):
    test_late_sql_failure_rolls_back_all_row_groups_even_if_caller_catches(
        pg_harness, "daily_runtime_outbound"
    )


def test_removing_entire_hold_group_cannot_hide_an_approved_admission(harness):
    from packages.persistence.daily_runtime_risk_schema import daily_runtime_outbound

    harness.enable()
    harness.admit(harness.request())
    with harness.engine.begin() as connection:
        for table in (daily_runtime_outbound, daily_runtime_hold_heads, daily_runtime_hold_events):
            connection.execute(sa.delete(table).where(table.c.account_id == harness.account))
    assert harness.counts()[2:] == (1, 0, 0, 0, 0, 0, 0, 0)
    with pytest.raises(DailyRuntimeRiskConflict, match="hold/outbound inventory"):
        harness.resolved()


@pytest.mark.parametrize("kind", ["admission", "assignment"])
@pytest.mark.parametrize("field", ["result", "writes", "valid_until", "snapshot"])
def test_altered_prepared_object_is_never_admitted(harness, kind, field):
    if kind == "admission":
        harness.enable()
        prepared = harness.prepare(harness.request())
        commit = harness.store.admit_prepared_in_transaction
    else:
        prepared = harness.prepare_assignment(harness.assignment, harness.last_owner_receipt)
        commit = harness.store.install_prepared_in_transaction
    changed = {
        "result": replace(prepared.result),
        "writes": (),
        "valid_until": NOW + timedelta(days=1),
        "snapshot": replace(prepared.snapshot, assignment=None),
    }[field]
    forged = replace(prepared, **{field: changed})
    before = harness.counts()
    with (
        _write_transaction(harness.engine) as connection,
        pytest.raises(DailyRuntimeRiskConflict, match="original store-produced"),
    ):
        commit(connection, forged, fence=harness.lease.fence)
    assert harness.counts() == before


def test_replaced_raw_and_resolved_snapshots_cannot_reuse_preparation_ownership(harness):
    request = harness.request()
    raw = harness.store.read_snapshot(
        account_id=harness.account,
        fence=harness.lease.fence,
        command_id=request["command_id"],
        input_refs=request["input_refs"],
    )
    with pytest.raises(DailyRuntimeRiskConflict, match="original store-produced"):
        harness.store.resolve_snapshot(replace(raw, producer=RuntimeProducerRawSnapshot(())))
    resolved = harness.store.resolve_snapshot(raw)
    with pytest.raises(DailyRuntimeRiskConflict, match="original store-produced"):
        harness.store.prepare_admission(
            replace(resolved, admissions=()), **{k: v for k, v in request.items() if k != "fence"}
        )


@pytest.mark.parametrize("retry", [False, True])
def test_admission_commit_performs_no_codec_risk_or_accounting_work(harness, monkeypatch, retry):
    import packages.persistence.daily_runtime_risk as daily_sql

    harness.enable()
    request = harness.request()
    if retry:
        harness.admit(request)
    prepared = harness.prepare(request)

    def forbidden(*args, **kwargs):
        raise AssertionError("expensive work reached account transaction")

    with monkeypatch.context() as patch:
        patch.setattr(codec, "encode_record", forbidden)
        patch.setattr(codec, "decode_record", forbidden)
        patch.setattr(harness.store.accounting, "advance", forbidden)
        patch.setattr(harness.store.accounting, "project", forbidden)
        patch.setattr(daily_sql, "evaluate_daily_risk", forbidden)
        patch.setattr(harness.reader, "resolve", forbidden)
        with _write_transaction(harness.engine) as connection:
            actual = harness.store.admit_prepared_in_transaction(
                connection, prepared, fence=harness.lease.fence
            )
    assert actual == prepared.result
    assert harness.counts()[2:] == (1, 1, 1, 0, 1, 0, 0, 0)


def test_assignment_commit_performs_no_codec_or_producer_resolution(harness, monkeypatch):
    prepared = harness.prepare_assignment(harness.assignment, harness.last_owner_receipt)

    def forbidden(*args, **kwargs):
        raise AssertionError("expensive work reached account transaction")

    with monkeypatch.context() as patch:
        patch.setattr(codec, "encode_record", forbidden)
        patch.setattr(codec, "decode_record", forbidden)
        patch.setattr(harness.reader, "resolve", forbidden)
        with _write_transaction(harness.engine) as connection:
            assert (
                harness.store.install_prepared_in_transaction(
                    connection, prepared, fence=harness.lease.fence
                )
                == harness.assignment
            )


def test_stalled_decoder_allows_actual_control_writer_commit_and_recheck_rejects(harness):
    from threading import Event

    harness.enable()
    request = harness.request()
    raw = harness.store.read_snapshot(
        account_id=harness.account,
        fence=harness.lease.fence,
        command_id=request["command_id"],
        input_refs=request["input_refs"],
    )
    entered, release = Event(), Event()

    class PausedCodec:
        encode_record = staticmethod(codec.encode_record)

        @staticmethod
        def decode_record(payload, cls):
            entered.set()
            assert release.wait(10), "test did not release decoder"
            return codec.decode_record(payload, cls)

    harness.store.codec = PausedCodec()
    before = harness.counts()
    with ThreadPoolExecutor(max_workers=2) as pool:
        read_future = pool.submit(harness.store.resolve_snapshot, raw)
        try:
            assert entered.wait(5)
            write_future = pool.submit(
                harness.controls.apply,
                harness.command(
                    OperationalControlCommandKind.PAUSE,
                    "concurrent-owner-pause",
                    OperationalControlState.PAUSED,
                ),
            )
            changed = write_future.result(timeout=5)
            assert changed.effective_state == OperationalControlState.PAUSED
            assert not release.is_set() and not read_future.done()
        finally:
            release.set()
        resolved = read_future.result(timeout=5)
    prepared = harness.store.prepare_admission(
        resolved, **{k: v for k, v in request.items() if k != "fence"}
    )
    with (
        _write_transaction(harness.engine) as connection,
        pytest.raises(DailyRuntimeRiskConflict, match=r"row inventory changed|immutable row bytes"),
    ):
        harness.store.admit_prepared_in_transaction(connection, prepared, fence=harness.lease.fence)
    assert harness.counts() == before


@pytest.mark.parametrize("mode", ["payload", "metadata", "storage_type", "aggregate", "rows"])
def test_invalid_or_oversized_source_storage_is_rejected_before_payload_transfer(harness, mode):
    request = harness.request()
    from packages.persistence.daily_runtime_risk import MAX_BYTES

    with harness.engine.begin() as connection:
        if mode == "payload":
            connection.execute(
                sa.update(records)
                .where(records.c.account_id == harness.account)
                .values(payload=b"x" * (MAX_BYTES + 1))
            )
        elif mode == "metadata":
            connection.execute(
                sa.update(records)
                .where(records.c.account_id == harness.account)
                .values(digest="x" * 10000)
            )
        elif mode == "storage_type":
            connection.exec_driver_sql(
                "UPDATE test_daily_runtime_records SET payload='text is not bytes' "
                "WHERE account_id=?",
                (harness.account,),
            )
        else:
            size, count = (MAX_BYTES, 33) if mode == "aggregate" else (1, 4097)
            connection.execute(
                sa.insert(records),
                [
                    dict(
                        account_id=harness.account,
                        name=f"invalid-{n}",
                        digest=SHA,
                        payload=b"x" * size,
                    )
                    for n in range(count)
                ],
            )
    statements = []

    def capture(connection, cursor, statement, parameters, context, many):
        if "FROM test_daily_runtime_records" in statement:
            statements.append(statement)

    sa.event.listen(harness.engine, "before_cursor_execute", capture)
    try:
        with pytest.raises(DailyRuntimeRiskConflict, match=r"bound|oversized"):
            harness.prepare(request)
    finally:
        sa.event.remove(harness.engine, "before_cursor_execute", capture)
    assert len(statements) == 1 and "count(" in statements[0].lower()
    assert harness.counts()[2:] == (0, 0, 0, 0, 0, 0, 0, 0)


def test_prepared_source_bytes_cannot_change_even_if_digest_metadata_is_unchanged(harness):
    harness.enable()
    request = harness.request()
    prepared = harness.prepare(request)
    with harness.engine.begin() as connection:
        connection.execute(
            sa.update(records)
            .where(records.c.account_id == harness.account, records.c.name.like("resolved-%"))
            .values(payload=b"same metadata changed body")
        )
    with (
        _write_transaction(harness.engine) as connection,
        pytest.raises(DailyRuntimeRiskConflict, match="immutable row bytes"),
    ):
        harness.store.admit_prepared_in_transaction(connection, prepared, fence=harness.lease.fence)
    assert harness.counts()[2:] == (0, 0, 0, 0, 0, 0, 0, 0)


def test_producer_cannot_bypass_bounded_capture_or_use_empty_positive_scope(harness, monkeypatch):
    from packages.persistence.daily_runtime_risk import RuntimeTableSnapshot

    request = harness.request()
    monkeypatch.setattr(
        harness.reader,
        "capture_in_transaction",
        lambda *a, **k: RuntimeProducerRawSnapshot(
            (RuntimeTableSnapshot(records, harness.account, ()),)
        ),
    )
    with pytest.raises(DailyRuntimeRiskConflict, match="bypassed shared bounded"):
        harness.prepare(request)
    monkeypatch.setattr(
        harness.reader, "capture_in_transaction", lambda *a, **k: RuntimeProducerRawSnapshot(())
    )
    with pytest.raises(DailyRuntimeRiskConflict, match="retained producer rows"):
        harness.prepare(request)


def test_aggregate_metadata_bound_precedes_transfer_even_for_valid_declared_columns(harness):
    from packages.persistence.daily_runtime_risk import RuntimeReadBudget

    table = sa.Table(
        "test_daily_metadata_footprint",
        fixture_meta,
        sa.Column("account_id", sa.String(128), primary_key=True),
        sa.Column("ordinal", sa.Integer, primary_key=True),
        sa.Column("label", sa.String(2048), nullable=False),
    )
    table.create(harness.engine)
    with harness.engine.begin() as connection:
        connection.execute(
            sa.insert(table),
            [dict(account_id=harness.account, ordinal=n, label="x" * 2048) for n in range(1024)],
        )
    with (
        _write_transaction(harness.engine) as connection,
        pytest.raises(DailyRuntimeRiskConflict, match="aggregate capture bound"),
    ):
        capture_runtime_table(
            connection, table, account_id=harness.account, budget=RuntimeReadBudget()
        )


def test_shared_budget_enforces_total_rows_across_individually_bounded_tables(harness):
    from packages.persistence.daily_runtime_risk import RuntimeReadBudget

    tables = tuple(
        sa.Table(
            f"test_daily_total_rows_{n}",
            fixture_meta,
            sa.Column("account_id", sa.String(128), primary_key=True),
            sa.Column("ordinal", sa.Integer, primary_key=True),
        )
        for n in range(5)
    )
    for table in tables:
        table.create(harness.engine)
        with harness.engine.begin() as connection:
            connection.execute(
                sa.insert(table), [dict(account_id=harness.account, ordinal=n) for n in range(4096)]
            )
    budget = RuntimeReadBudget()
    with _write_transaction(harness.engine) as connection:
        for table in tables[:4]:
            assert (
                len(
                    capture_runtime_table(
                        connection, table, account_id=harness.account, budget=budget
                    ).rows
                )
                == 4096
            )
        with pytest.raises(DailyRuntimeRiskConflict, match="aggregate capture bound"):
            capture_runtime_table(connection, tables[-1], account_id=harness.account, budget=budget)
    assert len(budget.captured) == 4


def test_preparation_cannot_write_an_inventory_exceeding_read_profile(harness, monkeypatch):
    import packages.persistence.daily_runtime_risk as daily_sql

    harness.enable()
    request = harness.request()
    raw = harness.store.read_snapshot(
        account_id=harness.account,
        fence=harness.lease.fence,
        command_id=request["command_id"],
        input_refs=request["input_refs"],
    )
    resolved = harness.store.resolve_snapshot(raw)
    retained_count = sum(len(item.rows) for item in (*raw.tables, *raw.producer.tables))
    before = harness.counts()
    # Tighten only this fixture's boundary to its admitted current footprint.
    monkeypatch.setattr(daily_sql, "MAX_TOTAL_ROWS", retained_count)
    with pytest.raises(DailyRuntimeRiskConflict, match="aggregate capture bound"):
        harness.store.prepare_admission(
            resolved, **{k: v for k, v in request.items() if k != "fence"}
        )
    assert harness.counts() == before


def test_advancing_capture_prepare_commit_clock_preserves_original_decision_hash(harness):
    harness.enable()
    request = harness.request()
    original = harness.prepare(request).result
    harness.clock.advance(timedelta(seconds=1))
    raw = harness.store.read_snapshot(
        account_id=harness.account,
        fence=harness.lease.fence,
        command_id=request["command_id"],
        input_refs=request["input_refs"],
    )
    harness.clock.advance(timedelta(seconds=1))
    resolved = harness.store.resolve_snapshot(raw)
    prepared = harness.store.prepare_admission(
        resolved, **{k: v for k, v in request.items() if k != "fence"}
    )
    harness.clock.advance(timedelta(seconds=1))
    with _write_transaction(harness.engine) as connection:
        actual = harness.store.admit_prepared_in_transaction(
            connection, prepared, fence=harness.lease.fence
        )
    assert actual.decision.approved
    assert actual.decision.semantic_sha256 == original.decision.semantic_sha256
    assert actual.evidence == original.evidence
    assert actual.evidence.produced_at == request["batch"].target.trigger.as_of == NOW
    assert actual.recorded_at == raw.receipt.validated_at == NOW + timedelta(seconds=1)
    assert actual.expires_at == original.expires_at == NOW + timedelta(seconds=5)
    assert harness.counts()[2:] == (1, 1, 1, 0, 1, 0, 0, 0)
    # An immutable retry is inert even after the original approval lifetime expires.
    harness.clock.advance(timedelta(seconds=3))
    assert harness.admit(request) == actual
    assert harness.counts()[2:] == (1, 1, 1, 0, 1, 0, 0, 0)


@pytest.mark.parametrize("phase", ["capture", "before_commit", "after_insert"])
def test_actual_clock_at_original_snapshot_expiry_cannot_publish_admission(harness, phase):
    harness.enable()
    request = harness.request()
    before = harness.counts()
    if phase == "capture":
        harness.clock.advance(timedelta(seconds=5))
        with pytest.raises(DailyRuntimeRiskConflict, match="expired before commit"):
            harness.prepare(request)
    else:
        prepared = harness.prepare(request)
        if phase == "before_commit":
            harness.clock.advance(timedelta(seconds=5))

        def expire(connection, cursor, statement, parameters, context, many):
            if phase == "after_insert" and statement.startswith(
                "INSERT INTO daily_runtime_outbound"
            ):
                harness.clock.advance(timedelta(seconds=5))

        sa.event.listen(harness.engine, "after_cursor_execute", expire)
        try:
            with (
                _write_transaction(harness.engine) as connection,
                pytest.raises(DailyRuntimeRiskConflict, match="expired before commit"),
            ):
                harness.store.admit_prepared_in_transaction(
                    connection, prepared, fence=harness.lease.fence
                )
        finally:
            sa.event.remove(harness.engine, "after_cursor_execute", expire)
    assert harness.counts() == before


@pytest.mark.parametrize("phase", ["capture", "commit"])
def test_clock_regression_never_relabels_the_original_decision(harness, phase):
    from packages.domain.account_coordinator import AccountCoordinatorError

    harness.enable()
    request = harness.request()
    before = harness.counts()
    harness.clock.advance(timedelta(seconds=1))
    prepared = harness.prepare(request)
    harness.clock.advance(timedelta(seconds=-1))
    with pytest.raises(AccountCoordinatorError, match="clock cannot regress"):
        if phase == "capture":
            harness.prepare(request)
        else:
            with _write_transaction(harness.engine) as connection:
                harness.store.admit_prepared_in_transaction(
                    connection, prepared, fence=harness.lease.fence
                )
    assert harness.counts() == before


def test_authenticated_context_must_match_original_snapshot_decision_frontier(harness):
    request = harness.request()
    raw = harness.store.read_snapshot(
        account_id=harness.account,
        fence=harness.lease.fence,
        command_id=request["command_id"],
        input_refs=request["input_refs"],
    )
    original = read(
        raw.producer,
        harness.account,
        "resolved-" + request["input_refs"].semantic_sha256,
        ResolvedRuntimeRiskInputs,
    )
    changed = replace(
        original,
        context=replace(
            original.context,
            point=replace(original.context.point, knowledge_at=NOW + timedelta(microseconds=1)),
        ),
    )
    payload = codec.encode_record(changed)
    with harness.engine.begin() as connection:
        connection.execute(
            sa.update(records)
            .where(records.c.account_id == harness.account, records.c.name.like("resolved-%"))
            .values(payload=payload, digest=sha256(payload).hexdigest())
        )
    with pytest.raises(DailyRuntimeRiskConflict, match="original decision frontier"):
        harness.admit(request)
    assert harness.counts()[2:] == (0, 0, 0, 0, 0, 0, 0, 0)


@pytest.mark.parametrize("elapsed", [timedelta(microseconds=999999), timedelta(seconds=1)])
def test_decision_cutoff_caps_actual_commit_even_when_snapshot_lifetime_remains(harness, elapsed):
    cutoff = START - timedelta(minutes=35)
    value = Harness(harness.engine, decision_at=cutoff - timedelta(seconds=1))
    value.enable()
    request = value.request()
    prepared = value.prepare(request)
    assert prepared.result.decision.approved
    assert prepared.valid_until == cutoff
    assert prepared.valid_until < prepared.result.evidence.produced_at + timedelta(seconds=5)
    value.clock.advance(elapsed)
    with _write_transaction(value.engine) as connection:
        if elapsed == timedelta(seconds=1):
            with pytest.raises(DailyRuntimeRiskConflict, match="expired before commit"):
                value.store.admit_prepared_in_transaction(
                    connection, prepared, fence=value.lease.fence
                )
        else:
            assert value.store.admit_prepared_in_transaction(
                connection, prepared, fence=value.lease.fence
            ).decision.approved
    assert value.counts()[2] == (1 if elapsed < timedelta(seconds=1) else 0)


def earlier_financial_observation(harness):
    refs = harness.base[3]
    harness.base = (
        *harness.base[:3],
        replace(
            refs,
            reconciliation=replace(
                refs.reconciliation,
                observation_started_at=harness.decision_at - timedelta(seconds=59),
                observation_received_through=harness.decision_at,
                completed_at=harness.decision_at,
            ),
        ),
        *harness.base[4:],
    )


@pytest.mark.parametrize("elapsed", [timedelta(microseconds=999999), timedelta(seconds=1)])
def test_first_financial_observation_caps_admission_actual_commit(harness, elapsed):
    harness.enable()
    earlier_financial_observation(harness)
    request = harness.request()
    prepared = harness.prepare(request)
    original_decision = prepared.result.decision
    assert original_decision.approved
    assert prepared.valid_until == NOW + timedelta(seconds=1)
    harness.clock.advance(elapsed)
    with _write_transaction(harness.engine) as connection:
        if elapsed == timedelta(seconds=1):
            with pytest.raises(DailyRuntimeRiskConflict, match="expired before commit"):
                harness.store.admit_prepared_in_transaction(
                    connection, prepared, fence=harness.lease.fence
                )
        else:
            actual = harness.store.admit_prepared_in_transaction(
                connection, prepared, fence=harness.lease.fence
            )
            assert actual.decision == original_decision
            assert actual.evidence.produced_at == request["batch"].target.trigger.as_of == NOW
    assert harness.counts()[2] == (1 if elapsed < timedelta(seconds=1) else 0)


def test_first_observation_expiring_after_insert_rolls_back_whole_admission(harness):
    harness.enable()
    earlier_financial_observation(harness)
    prepared = harness.prepare(harness.request())
    before = harness.counts()

    def expire(connection, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO daily_runtime_outbound"):
            harness.clock.advance(timedelta(seconds=1))

    sa.event.listen(harness.engine, "after_cursor_execute", expire)
    try:
        with (
            _write_transaction(harness.engine) as connection,
            pytest.raises(DailyRuntimeRiskConflict, match="expired before commit"),
        ):
            harness.store.admit_prepared_in_transaction(
                connection, prepared, fence=harness.lease.fence
            )
    finally:
        sa.event.remove(harness.engine, "after_cursor_execute", expire)
    assert harness.counts() == before


@pytest.mark.parametrize("elapsed", [timedelta(microseconds=999999), timedelta(seconds=1)])
def test_first_observation_caps_verified_owner_enable_transition(harness, monkeypatch, elapsed):
    earlier_financial_observation(harness)
    before = harness.counts()
    original = harness.store.install_prepared_in_transaction

    def advancing_commit(connection, prepared, *, fence):
        assert prepared.valid_until == NOW + timedelta(seconds=1)
        harness.clock.advance(elapsed)
        return original(connection, prepared, fence=fence)

    monkeypatch.setattr(harness.store, "install_prepared_in_transaction", advancing_commit)
    assignment = replace(
        harness.assignment,
        generation=2,
        previous_assignment_sha256=harness.assignment.semantic_sha256,
        enabled_for_new_exposure=True,
    )
    if elapsed == timedelta(seconds=1):
        with pytest.raises(DailyRuntimeRiskConflict, match="assignment evidence expired"):
            harness.install(assignment)
        assert harness.counts() == before
    else:
        harness.install(assignment)
        assert harness.assignment == assignment


def historical_admission(harness, request, *, capture_only=False):
    view = harness.store.inspect_prepared_admission(harness.prepare(request))
    with _write_transaction(harness.engine) as connection:
        raw = harness.store.capture_historical_admission_in_transaction(
            connection,
            account_id=harness.account,
            command_id=request["command_id"],
            expected_record_sha256=view.record_sha256,
        )
    return raw if capture_only else harness.store.resolve_historical_admission(raw)


@pytest.mark.parametrize("enabled", [False, True])
def test_owned_public_inspection_matches_original_producer_and_retry(harness, enabled):
    if enabled:
        harness.enable()
    request = harness.request()
    prepared = harness.prepare(request)
    first = harness.store.inspect_prepared_admission(prepared)
    assert first.admission == prepared.result
    assert first.prepared_commitments == request["prepared_commitments"]
    assert sha256(first.canonical_payload).hexdigest() == first.payload_sha256
    assert first.record_sha256 != first.admission.semantic_sha256
    assert all(binding.source_sha256 == first.record_sha256 for binding in first.bindings)
    harness.admit(request)
    retry = harness.store.inspect_prepared_admission(harness.prepare(request))
    historical = historical_admission(harness, request)
    assert first == retry == historical.admission
    assert bool(historical.admission.bindings) is enabled
    harness.store.require_admission_view(first)
    with pytest.raises(DailyRuntimeRiskConflict, match="original store-produced"):
        harness.store.require_admission_view(replace(first, record_sha256=SHA))
    with pytest.raises(DailyRuntimeRiskConflict, match="original store-produced"):
        harness.store.resolve_historical_admission(replace(historical.snapshot))


def test_historical_recheck_allows_later_control_and_assignment_but_pins_original(harness):
    harness.enable()
    request = harness.request()
    harness.admit(request)
    historical = historical_admission(harness, request)
    obligations = harness.resolved().obligations
    refs = replace(
        harness.base[3],
        obligations=obligations,
        heads=replace(
            harness.base[3].heads,
            capacity_sha256=obligations.semantic_sha256,
            effect_watermark=1,
        ),
    )
    harness.base = (*harness.base[:3], refs, *harness.base[4:])
    original = harness.assignment
    harness.install(
        replace(
            original,
            generation=3,
            previous_assignment_sha256=original.semantic_sha256,
            policy=replace(original.policy, max_order_quantity=D(100)),
        )
    )
    harness.controls.apply(
        harness.command(
            OperationalControlCommandKind.PAUSE, "later-pause", OperationalControlState.PAUSED
        )
    )
    with _write_transaction(harness.engine) as connection:
        harness.store.recheck_historical_admission_in_transaction(connection, historical)
    assert historical.admission.admission.evidence.assignment == original
    assert historical_admission(harness, request).admission == historical.admission


@pytest.mark.parametrize("change", ["payload", "missing_outbound", "extra_outbound"])
def test_historical_recheck_rejects_changed_selected_original_rows(harness, change):
    from packages.persistence.daily_runtime_risk_schema import (
        daily_runtime_admissions as admissions,
    )
    from packages.persistence.daily_runtime_risk_schema import (
        daily_runtime_outbound as outbound,
    )

    harness.enable()
    request = harness.request()
    harness.admit(request)
    historical = historical_admission(harness, request)
    with harness.engine.begin() as connection:
        if change == "payload":
            connection.execute(
                sa.update(admissions)
                .where(admissions.c.account_id == harness.account)
                .values(payload=b"invalid")
            )
        elif change == "missing_outbound":
            connection.execute(sa.delete(outbound).where(outbound.c.account_id == harness.account))
        else:
            row = dict(
                connection.execute(
                    sa.select(outbound).where(outbound.c.account_id == harness.account)
                )
                .mappings()
                .one()
            )
            row.update(outbound_id="f" * 64, intent_id="unexpected-original-intent")
            connection.execute(sa.insert(outbound).values(**row))
    with _write_transaction(harness.engine) as connection, pytest.raises(DailyRuntimeRiskConflict):
        harness.store.recheck_historical_admission_in_transaction(connection, historical)


def test_historical_capture_requires_exact_record_and_real_caller_transaction(harness):
    harness.enable()
    request = harness.request()
    view = harness.store.inspect_prepared_admission(harness.prepare(request))
    harness.admit(request)
    args = dict(
        account_id=harness.account,
        command_id=request["command_id"],
        expected_record_sha256=view.record_sha256,
    )
    with harness.engine.connect() as connection, pytest.raises(DailyRuntimeRiskConflict):
        harness.store.capture_historical_admission_in_transaction(connection, **args)
    for invalid in ({"expected_record_sha256": SHA}, {"command_id": "absent-command"}):
        with (
            _write_transaction(harness.engine) as connection,
            pytest.raises(DailyRuntimeRiskConflict),
        ):
            harness.store.capture_historical_admission_in_transaction(
                connection, **{**args, **invalid}
            )


def test_public_historical_capture_and_rechecks_never_decode_under_transaction(
    harness, monkeypatch
):
    import packages.persistence.daily_runtime_risk as daily_sql

    harness.enable()
    request = harness.request()
    harness.admit(request)
    historical = historical_admission(harness, request)
    current = harness.resolved()

    def forbidden(*args, **kwargs):
        raise AssertionError("expensive work reached historical SQL transaction")

    with monkeypatch.context() as patch:
        patch.setattr(codec, "encode_record", forbidden)
        patch.setattr(codec, "decode_record", forbidden)
        patch.setattr(harness.store.accounting, "advance", forbidden)
        patch.setattr(harness.store.accounting, "project", forbidden)
        patch.setattr(daily_sql, "evaluate_daily_risk", forbidden)
        with _write_transaction(harness.engine) as connection:
            raw = harness.store.capture_historical_admission_in_transaction(
                connection,
                account_id=harness.account,
                command_id=request["command_id"],
                expected_record_sha256=historical.admission.record_sha256,
            )
            harness.store.recheck_historical_admission_in_transaction(connection, historical)
            receipt = harness.store.recheck_snapshot_in_transaction(
                connection, current, fence=harness.lease.fence
            )
    assert receipt.fence == harness.lease.fence
    assert harness.store.resolve_historical_admission(raw).admission == historical.admission


def test_historical_decoder_stall_does_not_delay_actual_control_writer_commit(harness):
    from threading import Event

    harness.enable()
    request = harness.request()
    harness.admit(request)
    raw = historical_admission(harness, request, capture_only=True)
    entered, release = Event(), Event()

    class PausedCodec:
        encode_record = staticmethod(codec.encode_record)

        @staticmethod
        def decode_record(payload, cls):
            entered.set()
            assert release.wait(10)
            return codec.decode_record(payload, cls)

    harness.store.codec = PausedCodec()
    with ThreadPoolExecutor(max_workers=2) as pool:
        reading = pool.submit(harness.store.resolve_historical_admission, raw)
        try:
            assert entered.wait(5)
            writing = pool.submit(
                harness.controls.apply,
                harness.command(
                    OperationalControlCommandKind.PAUSE,
                    "historical-concurrent-pause",
                    OperationalControlState.PAUSED,
                ),
            )
            assert writing.result(timeout=5).effective_state == OperationalControlState.PAUSED
            assert not release.is_set() and not reading.done()
        finally:
            release.set()
        historical = reading.result(timeout=5)
    with _write_transaction(harness.engine) as connection:
        harness.store.recheck_historical_admission_in_transaction(connection, historical)


class AttemptFixtureReader(RetainedFixtureReader):
    """Explicit retained synthetic source fixture; production closure remains root-owned."""

    def __init__(self, account):
        super().__init__(account)
        self.owned = {}

    def _own(self, value):
        self.owned[id(value)] = value
        return value

    def prepare_attempt_source_read(self, references):
        from packages.persistence.daily_runtime_risk import RuntimeAttemptSourcePlan

        return self._own(RuntimeAttemptSourcePlan(references, object()))

    def capture_attempt_sources_in_transaction(self, connection, plan, *, account_id, budget):
        from packages.persistence.daily_runtime_risk import RuntimeAttemptSourceSnapshot

        assert self.owned.get(id(plan)) is plan and account_id == self.account
        return self._own(
            RuntimeAttemptSourceSnapshot(
                plan,
                (capture_runtime_table(connection, records, account_id=account_id, budget=budget),),
                object(),
            )
        )

    def resolve_attempt_sources(self, snapshot, *, admissions):
        from packages.persistence.daily_runtime_risk import (
            ResolvedRuntimeAttemptSources,
            RuntimeAttemptAccountingSource,
        )

        assert self.owned.get(id(snapshot)) is snapshot
        values = tuple(
            read(
                snapshot,
                self.account,
                "attempt-source-" + ref.semantic_sha256,
                RuntimeAttemptAccountingSource,
            )
            for ref in snapshot.plan.references
        )
        for value in values:
            assert any(
                ref.semantic_sha256 == admission.record_sha256
                for ref in value.source_references
                for admission in admissions
            )
        return self._own(ResolvedRuntimeAttemptSources(snapshot, values, object()))

    def recheck_attempt_sources_in_transaction(self, connection, resolved):
        assert self.owned.get(id(resolved)) is resolved
        assert connection.in_transaction()


def retain_attempt_source(h, source):
    from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
    from packages.domain.research_job_contracts import ObjectRef

    payload = codec.encode_record(source)
    reference = ContinuousEvidenceRef(
        "daily-attempt-accounting-source/1",
        ObjectRef(sha256(payload).hexdigest(), len(payload)),
        source.semantic_sha256,
    )
    with _write_transaction(h.engine) as connection:
        retain(connection, h.account, "attempt-source-" + reference.semantic_sha256, source)
    return reference


def pending_fixture(engine, *, two=False):
    from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
    from packages.domain.daily_attempt import daily_fence_reference, prepare_daily_attempt
    from packages.domain.daily_attempt_contracts import (
        DailyAttemptEnvelope,
        DailyAttemptEvent,
        DailyVenueSubmissionRequest,
    )
    from packages.domain.research_job_contracts import ObjectRef
    from packages.domain.stateful_venue_contracts import VenueSourceReference
    from packages.domain.submission_attempt import SubmissionAttemptState
    from packages.persistence.daily_runtime_risk import (
        RuntimeAttemptAccountingSource,
        daily_attempt_inventory_sha256,
    )
    from tests.unit.test_daily_attempt import reference
    from tests.unit.test_stateful_venue import model

    h = Harness(engine, two=two, observed=True)
    h.reader = AttemptFixtureReader(h.account)
    h.store.producers = h.reader
    h.enable()
    request = h.request()
    view = h.store.inspect_prepared_admission(h.prepare(request))
    h.admit(request)
    resolved = view.resolved
    installed = prepare_daily_commitments(
        state=resolved.state,
        snapshot=resolved.snapshot,
        batch=view.admission.decision.batch,
        decision=view.admission.decision,
        context=resolved.context,
        execution_policy=resolved.execution_policy,
        risk_policy=h.assignment.policy,
        accounting=PersonalAccounting(),
        attempt_namespace="daily-runtime-attempt",
    )
    assert installed.disposition == "installed"
    inventory = h.resolved().obligations
    context = replace(
        resolved.context,
        approved_snapshot=None,
        point=replace(
            resolved.context.point,
            reduction_sequence=installed.last_reduction_sequence + 1,
            stage=6,
        ),
    )
    snapshot = (
        PersonalAccounting()
        .project(state=installed.state, context=context, policy=resolved.execution_policy)
        .snapshot
    )
    heads = replace(
        h.base[3].heads,
        ledger_sha256=snapshot.journal_sha256,
        order_sha256=snapshot.order_sha256,
        capacity_sha256=inventory.semantic_sha256,
        attempt_sha256=daily_attempt_inventory_sha256(()),
        control_revision=h.control.sequence_number,
        lease_generation=h.lease.fencing_generation,
    )
    producer = VenueSourceReference(
        PIN, view.record_sha256, ObjectRef(view.payload_sha256, len(view.canonical_payload))
    )
    venue = model()
    preparations = []
    for hold in inventory.bindings:
        submission = next(
            item
            for item in installed.state.submissions
            if item.order_id == hold.commitment.order_id
        )
        venue_request = DailyVenueSubmissionRequest(
            submission=submission,
            original_commitment=hold.commitment,
            source_account_id=h.account,
            source_account_binding_sha256=h.assignment.account_binding_sha256,
            venue_account_id=venue.account_id,
            venue_model=reference(venue),
            original_admission_sha256=view.admission.semantic_sha256,
        )
        preparations.append(
            prepare_daily_attempt(
                request=venue_request,
                original_admission=view.admission,
                admission_source=producer,
                original_hold=hold,
                prepared_at=NOW,
            )
        )
    source = RuntimeAttemptAccountingSource(
        account_id=h.account,
        coordinator_command_id="consume-admission",
        coordinator_sequence=1,
        state=installed.state,
        context=context,
        execution_policy=resolved.execution_policy,
        obligations=inventory,
        heads=heads,
        fence=daily_fence_reference(h.coordinator.revalidate(h.lease.fence)),
        checked_at=NOW,
        valid_until=NOW + timedelta(seconds=5),
        accounting_command=None,
        source_references=(
            ContinuousEvidenceRef(
                "daily-admission-producer/1", producer.object_ref, view.record_sha256
            ),
        ),
    )
    source_ref = retain_attempt_source(h, source)
    envelopes = tuple(
        DailyAttemptEnvelope(
            account_id=h.account,
            coordinator_command_id=source.coordinator_command_id,
            coordinator_sequence=source.coordinator_sequence,
            source_ref=source_ref,
            event=DailyAttemptEvent(
                attempt_id=item.attempt_id,
                sequence=1,
                previous_event_sha256=None,
                state=SubmissionAttemptState.PENDING,
                recorded_at=NOW,
            ),
        )
        for item in preparations
    )
    return h, source, envelopes, tuple(preparations)


def prepare_attempt(h, envelopes, preparations=(), **kwargs):
    raw = h.store.read_attempt_snapshot(
        account_id=h.account, fence=h.lease.fence, envelopes=envelopes, preparations=preparations
    )
    return h.store.prepare_attempt_mutation(h.store.resolve_snapshot(raw), **kwargs)


def prepare_parent_fixture(h, source):
    """Actual journal/lease FK parent fixture; actual C checkpoint composer has separate tests."""
    from packages.domain.daily_observed_hold_contracts import RuntimeObservedHoldSource
    from packages.persistence.daily_runtime_risk import RuntimeAttemptAccountingSource
    from packages.persistence.durable_journal import SqlDurableJournal

    journal = SqlDurableJournal(
        h.engine,
        codec=codec,
        record_types={
            "fixture-parent/1": RuntimeAttemptAccountingSource,
            "fixture-observed-parent/1": RuntimeObservedHoldSource,
        },
    )
    key = JournalKey(
        "coordinator", "parent-" + h.account, h.account, "fixture-parent", "synthetic", SHA
    )
    head = journal.read_head(key)
    schema = (
        "fixture-observed-parent/1"
        if type(source) is RuntimeObservedHoldSource
        else "fixture-parent/1"
    )
    item = JournalRecord(source.coordinator_command_id, schema, codec.encode_record(source))
    prepared = journal.prepare_append(
        key, JournalAppend(source.coordinator_command_id, source.semantic_sha256, head, (item,))
    )
    receipt = prepared.receipt
    values = dict(
        account_id=h.account,
        command_id=source.coordinator_command_id,
        scope_sha256=SHA,
        sequence=source.coordinator_sequence,
        commit_sha256=source.semantic_sha256,
        previous_commit_sha256=None if source.coordinator_sequence == 1 else SHA,
        checkpoint_sha256=SHA,
        journal_key_sha256=key.semantic_sha256,
        journal_receipt_sha256=receipt.semantic_sha256,
        canonical_payload=b"explicit relational parent fixture",
        recorded_at=source.checked_at.isoformat(),
        owner_id=source.fence.fence.owner_id,
        lease_id=source.fence.fence.lease_id,
        fencing_generation=source.fence.fence.fencing_generation,
        lease_sha256=source.fence.lease_sha256,
        policy_sha256=source.fence.policy_sha256,
        valid_until=source.valid_until.isoformat(),
        receipt_sha256=source.fence.original_receipt_sha256,
    )
    return journal, prepared, values


def commit_attempt(h, source, prepared, *, parent=True):
    parent_write = prepare_parent_fixture(h, source) if parent and not prepared.retry else None
    with _write_transaction(h.engine) as connection:
        result = h.store.commit_attempt_prepared_in_transaction(
            connection, prepared, fence=h.lease.fence
        )
        if parent_write is not None:
            journal, append, values = parent_write
            journal.append_in_transaction(connection, append)
            connection.execute(sa.insert(continuous_account_commits).values(**values))
        return result


def test_actual_pending_consumption_preserves_original_holds_and_exact_retry(harness):
    h, source, envelopes, preparations = pending_fixture(harness.engine, two=True)
    prepared = prepare_attempt(h, envelopes, preparations)
    result = commit_attempt(h, source, prepared)
    assert all(item.state.value == "pending" for item in result.attempts)
    assert result.obligations == source.obligations
    assert h.counts()[3:] == (2, 2, 2, 2, 2, 2, 0)
    restored = h.resolved()
    assert restored.attempts == result.attempts and restored.obligations == result.obligations
    h.clock.advance(timedelta(seconds=6))
    retry = prepare_attempt(h, envelopes, preparations)
    assert retry.retry and retry.writes == () and retry.dispatch_appends == ()
    assert commit_attempt(h, source, retry) == result
    assert h.counts()[3:] == (2, 2, 2, 2, 2, 2, 0)


def test_missing_deferred_parent_rolls_back_consumption_events_and_heads(harness):
    h, source, envelopes, preparations = pending_fixture(harness.engine)
    before = h.counts()
    prepared = prepare_attempt(h, envelopes, preparations)
    with pytest.raises(sa.exc.IntegrityError):
        commit_attempt(h, source, prepared, parent=False)
    assert h.counts() == before


def activation_fixture(h, pending_source, pending_result, *, price="110"):
    from packages.application.daily_runtime_activation import prepare_daily_runtime_activation
    from packages.domain.accounting_contracts import AccountingCommand
    from packages.domain.daily_attempt import (
        daily_fence_reference,
        prepare_daily_activation,
        prepare_daily_dispatch,
    )
    from packages.domain.daily_attempt_contracts import (
        DailyAttemptEnvelope,
        DailyAttemptEvent,
        DailyDispatchClaim,
        DailyDispatchRecord,
    )
    from packages.domain.research_job_contracts import ObjectRef
    from packages.domain.submission_attempt import SubmissionAttemptState
    from packages.persistence.daily_runtime_risk import (
        RuntimeAttemptAccountingSource,
        daily_attempt_inventory_sha256,
    )
    from packages.persistence.durable_journal import SqlDurableJournal
    from tests.unit.test_daily_attempt import rebind_case
    from tests.unit.test_daily_risk_snapshot import build
    from tests.unit.test_daily_target_conversion import EXECUTION

    h.coordinator.release(h.lease.fence)
    h.clock.instant = START
    h.lease = h.coordinator.acquire("owner")
    fence = daily_fence_reference(h.coordinator.revalidate(h.lease.fence))
    state, policy = pending_result.accounting_state, pending_source.execution_policy
    context = replace(
        pending_source.context,
        economic_at=START,
        expected_mark_session=EXECUTION,
        point=replace(pending_source.context.point, knowledge_at=START, frontier_sequence=2),
    )
    port = PersonalAccounting()
    for index, mark in enumerate(state.marks, context.point.reduction_sequence + 1):
        observed = replace(
            mark,
            mark_id="fresh-" + mark.mark_id,
            price=D(price),
            session=EXECUTION,
            economic_at=START,
            knowledge_at=START,
            basis="runtime_quote_ask_v1",
        )
        context = replace(context, point=replace(context.point, reduction_sequence=index, stage=2))
        transition = port.advance(
            state=state,
            command=AccountingCommand(observed.mark_id, observed),
            context=context,
            policy=policy,
        )
        assert transition.disposition == "applied", transition.reasons
        state = transition.state
    context = replace(context, point=replace(context.point, reduction_sequence=index + 1, stage=5))
    snapshot = port.project(state=state, context=context, policy=policy).snapshot
    batch = replace(
        pending_result.attempts[0].preparation.original_admission.decision.batch,
        snapshot_sha256=snapshot.semantic_sha256,
    )
    case = runtime_case(
        snapshot=snapshot,
        batch=batch,
        phase="activation",
        now=START,
        bindings=pending_result.obligations.bindings,
    )
    heads = replace(
        case[3].heads,
        attempt_sha256=daily_attempt_inventory_sha256(pending_result.attempts),
        control_revision=h.control.sequence_number,
        lease_generation=h.lease.fencing_generation,
        effect_watermark=1,
    )
    inputs = replace(
        case[3],
        heads=heads,
        reconciliation=replace(case[3].reconciliation, heads=heads),
        accepted_intent_ids=tuple(
            sorted(item.commitment.intent_id for item in pending_result.obligations.bindings)
        ),
    )
    case = rebind_case(
        (h.assignment, snapshot, batch, inputs, h.producer_map, START), account_id=h.account
    )
    evidence = build(case)
    decision = evaluate_daily_risk(h.assignment.policy, snapshot, batch, evidence, START)
    assert decision.approved, decision.reasons
    dispatches = []
    for attempt in pending_result.attempts:
        hold = next(
            binding
            for binding in pending_result.obligations.bindings
            if binding.commitment.commitment_id
            == attempt.preparation.original_hold.commitment.commitment_id
        )
        activation = prepare_daily_activation(
            preparation=attempt.preparation,
            current_hold=hold,
            snapshot=snapshot,
            evidence=evidence,
            decision=decision,
            heads=heads,
            fence=fence,
            checked_at=START,
        )
        dispatches.append(
            prepare_daily_dispatch(
                attempt=attempt,
                activation=activation,
                command_id="send-" + attempt.attempt_id,
                dispatched_at=START,
            )
        )
    context = replace(
        context,
        approved_snapshot=snapshot,
        risk_policy_sha256=h.assignment.policy.semantic_sha256,
        point=replace(
            context.point, reduction_sequence=context.point.reduction_sequence + 1, stage=6
        ),
    )
    activation = prepare_daily_runtime_activation(
        state=state,
        context=context,
        execution_policy=policy,
        attempts=pending_result.attempts,
        dispatches=tuple(dispatches),
        accounting=port,
    )
    source = RuntimeAttemptAccountingSource(
        account_id=h.account,
        coordinator_command_id="activate-and-send",
        coordinator_sequence=2,
        state=state,
        context=context,
        execution_policy=policy,
        obligations=pending_result.obligations,
        heads=heads,
        fence=fence,
        checked_at=START,
        valid_until=min(item.activation.expires_at for item in dispatches),
        accounting_command=activation.command,
        source_references=pending_source.source_references,
    )
    source_ref = retain_attempt_source(h, source)
    journal = SqlDurableJournal(
        h.engine, codec=codec, record_types={"daily-dispatch/1": DailyDispatchRecord}
    )
    request = dispatches[0].preparation.request
    scope = content_digest(
        (
            "daily-dispatch-scope/1",
            request.source_account_id,
            request.source_account_binding_sha256,
            request.venue_account_id,
            request.venue_model,
        )
    )
    key = JournalKey(
        "coordinator", "dispatch-" + h.account, h.account, "daily-dispatch/1", "synthetic", scope
    )
    head = empty_head(key)
    appends, envelopes = [], []
    for dispatch in dispatches:
        encoded = codec.encode_record(dispatch)
        item = JournalRecord(dispatch.record_id, "daily-dispatch/1", encoded)
        append = journal.prepare_append(
            key, JournalAppend(dispatch.command_id, dispatch.semantic_sha256, head, (item,))
        )
        head = append.receipt.committed_head
        claim = DailyDispatchClaim(
            record=dispatch,
            receipt=append.receipt,
            record_ref=ObjectRef(sha256(encoded).hexdigest(), len(encoded)),
        )
        event = DailyAttemptEvent(
            attempt_id=dispatch.preparation.attempt_id,
            sequence=2,
            previous_event_sha256=next(
                a
                for a in pending_result.attempts
                if a.attempt_id == dispatch.preparation.attempt_id
            )
            .events[-1]
            .semantic_sha256,
            state=SubmissionAttemptState.IN_FLIGHT,
            recorded_at=START,
            dispatch=claim,
        )
        envelopes.append(
            DailyAttemptEnvelope(
                account_id=h.account,
                coordinator_command_id=source.coordinator_command_id,
                coordinator_sequence=source.coordinator_sequence,
                event=event,
                source_ref=source_ref,
            )
        )
        appends.append(append)
    return source, tuple(envelopes), journal, tuple(appends)


@pytest.mark.parametrize("price", ["90", "110"])
def test_actual_first_send_replaces_complete_two_hold_batch_without_acknowledgement(harness, price):
    h, pending_source, envelopes, preparations = pending_fixture(harness.engine, two=True)
    pending = commit_attempt(h, pending_source, prepare_attempt(h, envelopes, preparations))
    source, sent, journal, appends = activation_fixture(h, pending_source, pending, price=price)
    prepared = prepare_attempt(h, sent, dispatch_journal=journal, dispatch_appends=appends)
    result = commit_attempt(h, source, prepared)
    assert all(attempt.state.value == "in_flight" for attempt in result.attempts)
    assert result.accounting_state.broker_events == pending.accounting_state.broker_events == ()
    assert all(binding.commitment.state == "active" for binding in result.obligations.bindings)
    assert all(
        (new.commitment.reserved_cash > old.commitment.reserved_cash) == (D(price) > 100)
        for new, old in zip(result.obligations.bindings, pending.obligations.bindings, strict=True)
    )
    restored = h.resolved()
    assert restored.attempts == result.attempts and restored.obligations == result.obligations
    assert h.counts()[3:] == (4, 2, 2, 2, 4, 2, 0)


def later_attempt_source(h, previous_source, result, *, at=None, command="observe", sequence=None):
    from packages.domain.daily_attempt import daily_fence_reference
    from packages.persistence.daily_runtime_risk import daily_attempt_inventory_sha256

    at = previous_source.checked_at + timedelta(milliseconds=100) if at is None else at
    if at >= h.lease.expires_at:
        h.coordinator.release(h.lease.fence)
    h.clock.instant = at
    if at >= h.lease.expires_at:
        h.lease = h.coordinator.acquire("owner")
    context = replace(
        previous_source.context,
        approved_snapshot=None,
        point=replace(
            previous_source.context.point,
            knowledge_at=at,
            reduction_sequence=previous_source.context.point.reduction_sequence + 1,
        ),
    )
    projected = (
        PersonalAccounting()
        .project(
            state=result.accounting_state, context=context, policy=previous_source.execution_policy
        )
        .snapshot
    )
    heads = replace(
        previous_source.heads,
        ledger_sha256=projected.journal_sha256,
        order_sha256=projected.order_sha256,
        capacity_sha256=result.obligations.semantic_sha256,
        attempt_sha256=daily_attempt_inventory_sha256(result.attempts),
        effect_watermark=previous_source.heads.effect_watermark + 1,
        lease_generation=h.lease.fencing_generation,
    )
    return replace(
        previous_source,
        coordinator_command_id=command,
        coordinator_sequence=previous_source.coordinator_sequence + 1
        if sequence is None
        else sequence,
        state=result.accounting_state,
        context=context,
        obligations=result.obligations,
        heads=heads,
        fence=daily_fence_reference(h.coordinator.revalidate(h.lease.fence)),
        checked_at=at,
        valid_until=at + timedelta(seconds=1),
        accounting_command=None,
    )


def envelope_for(source, source_ref, event):
    from packages.domain.daily_attempt_contracts import DailyAttemptEnvelope

    return DailyAttemptEnvelope(
        account_id=source.account_id,
        coordinator_command_id=source.coordinator_command_id,
        coordinator_sequence=source.coordinator_sequence,
        event=event,
        source_ref=source_ref,
    )


def test_unknown_and_positive_resolution_keep_full_history_and_reserves(harness):
    from packages.domain.submission_attempt import SubmissionAttemptState
    from tests.unit.test_daily_attempt import event_after, observed_outcome

    h, original, envelopes, preparations = pending_fixture(harness.engine)
    pending = commit_attempt(h, original, prepare_attempt(h, envelopes, preparations))
    source, sent, journal, appends = activation_fixture(h, original, pending)
    result = commit_attempt(
        h, source, prepare_attempt(h, sent, dispatch_journal=journal, dispatch_appends=appends)
    )
    held = result.obligations
    unknown_source = later_attempt_source(h, source, result, command="delivery-unknown")
    event = event_after(
        result.attempts[0],
        SubmissionAttemptState.UNKNOWN,
        unknown_source.checked_at,
        reason="ambiguous-delivery",
    )
    envelope = envelope_for(unknown_source, retain_attempt_source(h, unknown_source), event)
    unknown = commit_attempt(h, unknown_source, prepare_attempt(h, (envelope,)))
    assert unknown.obligations == held and unknown.attempts[0].state.value == "unknown"
    resolved_source = later_attempt_source(
        h, unknown_source, unknown, command="positive-resolution"
    )
    outcome = observed_outcome(unknown.attempts[0], resolved_source.checked_at)
    event = event_after(
        unknown.attempts[0],
        SubmissionAttemptState.RESOLVED,
        resolved_source.checked_at,
        outcome=outcome,
    )
    envelope = envelope_for(resolved_source, retain_attempt_source(h, resolved_source), event)
    resolved = commit_attempt(h, resolved_source, prepare_attempt(h, (envelope,)))
    assert resolved.obligations == held and len(resolved.attempts[0].events) == 4
    assert h.resolved().attempts == resolved.attempts
    retry = prepare_attempt(h, envelopes, preparations)
    assert retry.retry and commit_attempt(h, original, retry) == pending


def test_actual_expired_unsent_release_posts_terminal_hold_with_original_lineage(harness):
    from packages.domain.accounting_contracts import AccountingCommand, ReleaseRuntimeUnsent
    from packages.domain.daily_attempt_contracts import DailyUnsentProof
    from packages.domain.submission_attempt import SubmissionAttemptState
    from tests.unit.test_daily_attempt import event_after

    h, original, envelopes, preparations = pending_fixture(harness.engine)
    pending = commit_attempt(h, original, prepare_attempt(h, envelopes, preparations))
    source = later_attempt_source(h, original, pending, at=END, command="expire-unsent")
    attempt = pending.attempts[0]
    hold = attempt.preparation.original_hold.commitment
    proof = DailyUnsentProof(
        account_id=h.account,
        attempt_id=attempt.attempt_id,
        request_sha256=attempt.preparation.request.semantic_sha256,
        attempt_history_sha256=attempt.semantic_sha256,
        commitment_sha256=hold.semantic_sha256,
        heads=source.heads,
        fence=source.fence,
        checked_at=source.checked_at,
        reason="expired",
        owner_command=None,
    )
    payload = ReleaseRuntimeUnsent(
        account_id=h.account,
        commitment_id=hold.commitment_id,
        expected_commitment_sha256=hold.semantic_sha256,
        source_state_sha256=source.state.semantic_sha256,
        attempt_history_sha256=attempt.semantic_sha256,
        locked_unsent_proof_sha256=proof.semantic_sha256,
        proof_at=source.checked_at,
        reason="expired",
    )
    source = replace(
        source, accounting_command=AccountingCommand("release-expired-runtime", payload)
    )
    event = event_after(
        attempt, SubmissionAttemptState.ABANDONED, source.checked_at, unsent_proof=proof
    )
    envelope = envelope_for(source, retain_attempt_source(h, source), event)
    result = commit_attempt(h, source, prepare_attempt(h, (envelope,)))
    current = result.obligations.bindings[0]
    assert current.source_sha256 == pending.obligations.bindings[0].source_sha256
    assert current.commitment.state == "terminal" and current.commitment.reserved_cash == 0
    assert result.attempts[0].state.value == "abandoned"
    assert h.resolved().obligations == result.obligations


@pytest.mark.parametrize(
    "target",
    [
        "daily_runtime_attempt_events",
        "daily_runtime_attempt_heads",
        "daily_runtime_hold_events",
        "daily_runtime_hold_heads",
        "personal_journal_entries",
    ],
)
def test_first_send_failure_rolls_back_events_reserves_and_dispatch_journal(harness, target):
    from packages.persistence.durable_journal_schema import journal_entries

    h, original, envelopes, preparations = pending_fixture(harness.engine, two=True)
    pending = commit_attempt(h, original, prepare_attempt(h, envelopes, preparations))
    source, sent, journal, appends = activation_fixture(h, original, pending)
    prepared = prepare_attempt(h, sent, dispatch_journal=journal, dispatch_appends=appends)
    before = h.counts()
    with h.engine.connect() as connection:
        journal_before = connection.scalar(sa.select(sa.func.count()).select_from(journal_entries))

    def fail(connection, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO " + target) or statement.startswith(
            "UPDATE " + target
        ):
            raise RuntimeError("controlled lifecycle write failure")

    sa.event.listen(h.engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(RuntimeError, match="controlled lifecycle"):
            commit_attempt(h, source, prepared)
    finally:
        sa.event.remove(h.engine, "before_cursor_execute", fail)
    assert h.counts() == before
    with h.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(journal_entries))
            == journal_before
        )


@pytest.mark.parametrize("phase", ["capture", "commit", "after_event_insert"])
def test_pending_original_expiry_is_not_refreshed_by_later_capture_or_commit(harness, phase):
    h, source, envelopes, preparations = pending_fixture(harness.engine)
    before = h.counts()
    if phase == "capture":
        h.clock.advance(timedelta(seconds=5))
        with pytest.raises(DailyRuntimeRiskConflict, match=r"capture time|expired"):
            prepare_attempt(h, envelopes, preparations)
    else:
        prepared = prepare_attempt(h, envelopes, preparations)
        if phase == "commit":
            h.clock.advance(timedelta(seconds=5))

        def expire(connection, cursor, statement, parameters, context, many):
            if statement.startswith("INSERT INTO daily_runtime_attempt_events"):
                h.clock.instant = prepared.valid_until

        if phase == "after_event_insert":
            sa.event.listen(h.engine, "after_cursor_execute", expire)
        try:
            with pytest.raises(DailyRuntimeRiskConflict, match="expired before commit"):
                commit_attempt(h, source, prepared)
        finally:
            if phase == "after_event_insert":
                sa.event.remove(h.engine, "after_cursor_execute", expire)
    assert h.counts() == before


@pytest.mark.parametrize("first_send", [False, True])
def test_lifecycle_commit_has_no_codec_accounting_or_source_resolution(
    harness, monkeypatch, first_send
):
    h, source, envelopes, preparations = pending_fixture(harness.engine)
    prepared = prepare_attempt(h, envelopes, preparations)
    if first_send:
        pending = commit_attempt(h, source, prepared)
        source, envelopes, journal, appends = activation_fixture(h, source, pending)
        prepared = prepare_attempt(h, envelopes, dispatch_journal=journal, dispatch_appends=appends)
    parent_journal, parent_append, values = prepare_parent_fixture(h, source)

    def forbidden(*args, **kwargs):
        raise AssertionError("expensive work inside lifecycle SQL")

    with monkeypatch.context() as patch:
        patch.setattr(codec, "encode_record", forbidden)
        patch.setattr(codec, "decode_record", forbidden)
        patch.setattr(h.store.accounting, "advance", forbidden)
        patch.setattr(h.store.accounting, "project", forbidden)
        patch.setattr(h.reader, "resolve_attempt_sources", forbidden)
        with _write_transaction(h.engine) as connection:
            result = h.store.commit_attempt_prepared_in_transaction(
                connection, prepared, fence=h.lease.fence
            )
            parent_journal.append_in_transaction(connection, parent_append)
            connection.execute(sa.insert(continuous_account_commits).values(**values))
    assert result.attempts[0].state.value == ("in_flight" if first_send else "pending")


def test_postgres_deferred_parent_failure_rolls_back_attempt_group(pg_harness):
    test_missing_deferred_parent_rolls_back_consumption_events_and_heads(pg_harness)


def test_postgres_actual_pending_group_and_original_retry(pg_harness):
    test_actual_pending_consumption_preserves_original_holds_and_exact_retry(pg_harness)


@pytest.mark.parametrize("field", ["result", "writes", "valid_until", "snapshot"])
def test_copied_lifecycle_preparation_cannot_change_any_validated_value(harness, field):
    h, _source, envelopes, preparations = pending_fixture(harness.engine)
    prepared = prepare_attempt(h, envelopes, preparations)
    changed = {
        "result": replace(prepared.result, coordinator_command_id="changed"),
        "writes": (),
        "valid_until": END,
        "snapshot": replace(prepared.snapshot),
    }[field]
    before = h.counts()
    with (
        _write_transaction(h.engine) as connection,
        pytest.raises(DailyRuntimeRiskConflict, match="original store-produced"),
    ):
        h.store.commit_attempt_prepared_in_transaction(
            connection, replace(prepared, **{field: changed}), fence=h.lease.fence
        )
    assert h.counts() == before


@pytest.mark.parametrize("change", ["source", "control", "fence"])
def test_lifecycle_rechecks_exact_source_control_and_fence_before_any_write(harness, change):
    h, source, envelopes, preparations = pending_fixture(harness.engine)
    prepared = prepare_attempt(h, envelopes, preparations)
    before = h.counts()
    if change == "source":
        with h.engine.begin() as connection:
            connection.execute(
                sa.update(records)
                .where(records.c.account_id == h.account, records.c.name.like("attempt-source-%"))
                .values(payload=b"changed")
            )
    elif change == "control":
        h.controls.apply(
            h.command(
                OperationalControlCommandKind.PAUSE,
                "pause-before-send",
                OperationalControlState.PAUSED,
            )
        )
    else:
        h.coordinator.release(h.lease.fence)
        h.coordinator.acquire("different-owner")
    with pytest.raises((DailyRuntimeRiskConflict, AccountLeaseOwnershipLost)):
        commit_attempt(h, source, prepared)
    assert h.counts() == before


def test_partial_first_send_batch_cannot_publish_any_dispatch_or_reserve_change(harness):
    h, original, envelopes, preparations = pending_fixture(harness.engine, two=True)
    pending = commit_attempt(h, original, prepare_attempt(h, envelopes, preparations))
    _source, sent, journal, appends = activation_fixture(h, original, pending)
    before = h.counts()
    with pytest.raises(ValueError, match="complete current risk batch"):
        prepare_attempt(h, sent[:1], dispatch_journal=journal, dispatch_appends=appends[:1])
    assert h.counts() == before


@pytest.mark.parametrize("change", ["head", "missing_head", "oversized_event"])
def test_complete_indexed_attempt_history_cannot_be_replaced_by_head_or_hidden(harness, change):
    from packages.persistence.daily_runtime_risk_schema import (
        daily_runtime_attempt_events as events,
    )
    from packages.persistence.daily_runtime_risk_schema import daily_runtime_attempt_heads as heads

    h, source, envelopes, preparations = pending_fixture(harness.engine)
    commit_attempt(h, source, prepare_attempt(h, envelopes, preparations))
    with h.engine.begin() as connection:
        if change == "head":
            connection.execute(
                sa.update(heads).where(heads.c.account_id == h.account).values(attempt_sha256=SHA)
            )
        elif change == "missing_head":
            connection.execute(sa.delete(heads).where(heads.c.account_id == h.account))
        else:
            connection.exec_driver_sql("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                sa.update(events)
                .where(events.c.account_id == h.account)
                .values(payload=b"x" * (1024 * 1024 + 1))
            )
            connection.exec_driver_sql("PRAGMA ignore_check_constraints = OFF")
    with pytest.raises(DailyRuntimeRiskConflict, match=r"head inventory|oversized"):
        h.resolved()


def test_stalled_lifecycle_source_resolution_does_not_block_actual_writer(harness, monkeypatch):
    from threading import Event

    h, source, envelopes, preparations = pending_fixture(harness.engine)
    raw = h.store.read_attempt_snapshot(
        account_id=h.account, fence=h.lease.fence, envelopes=envelopes, preparations=preparations
    )
    entered, release = Event(), Event()
    original = h.reader.resolve_attempt_sources

    def stalled(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(h.reader, "resolve_attempt_sources", stalled)
    with ThreadPoolExecutor(max_workers=2) as pool:
        reading = pool.submit(h.store.resolve_snapshot, raw)
        try:
            assert entered.wait(5)
            writing = pool.submit(
                h.controls.apply,
                h.command(
                    OperationalControlCommandKind.PAUSE,
                    "concurrent-lifecycle-pause",
                    OperationalControlState.PAUSED,
                ),
            )
            assert writing.result(timeout=5).effective_state == OperationalControlState.PAUSED
            assert not release.is_set() and not reading.done()
        finally:
            release.set()
        snapshot = reading.result(timeout=5)
    prepared = h.store.prepare_attempt_mutation(snapshot)
    with pytest.raises(DailyRuntimeRiskConflict, match=r"row inventory|immutable row"):
        commit_attempt(h, source, prepared)


def test_attempt_lifecycle_has_no_default_passing_source_resolver(harness):
    h, _source, envelopes, preparations = pending_fixture(harness.engine)
    h.store.producers = RetainedFixtureReader(h.account)
    with pytest.raises(DailyRuntimeRiskConflict, match="concrete retained-source producer"):
        prepare_attempt(h, envelopes, preparations)
