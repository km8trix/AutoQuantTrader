"""Real engine/capture/B/C stores; historical runtime producer is explicitly synthetic.

The fixture authenticates its own retained typed rows, not a provider, broker,
clock service, or owner command outside this test. No listening process exists.
"""

from dataclasses import dataclass, replace
from datetime import timedelta
from hashlib import sha256
from weakref import WeakValueDictionary

import pytest
import sqlalchemy as sa

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.application.continuous_account_transition import ContinuousAccountTransitionPreparer
from packages.application.continuous_source_events import (
    compile_continuous_bootstrap,
    project_continuous_daily_frontier,
)
from packages.application.personal_forward_capture import replay_capture
from packages.application.reference_strategy import ReferenceStrategy
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.account_coordinator import AccountLeasePolicy
from packages.domain.continuous_composition_contracts import (
    FORWARD_CLOSURE_SCHEMA,
    SYNTHETIC_BOOTSTRAP_SCHEMA,
    SyntheticContinuousBootstrap,
)
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
from packages.domain.continuous_persistence_contracts import (
    CONTINUOUS_COMMIT_SCHEMA,
    ContinuousAccountCommit,
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.daily_runtime_contracts import RuntimeProducerMap
from packages.domain.daily_runtime_risk import (
    build_daily_runtime_evidence,
    runtime_source_value_sha256,
)
from packages.domain.forward_contracts import ForwardDataState
from packages.domain.operational_control import (
    OperationalControlCommandKind,
    OperationalControlState,
)
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.research_dataset import modeled_daily_availability
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.continuous_account_schema import (
    CONTINUOUS_ACCOUNT_TABLES,
    continuous_account_commits,
)
from packages.persistence.continuous_composition import (
    ContinuousCompositionError,
    ContinuousProducerPlan,
    ContinuousProducerSnapshot,
    ResolvedContinuousProducerClosure,
    SqlContinuousCommitComposer,
)
from packages.persistence.continuous_forward_sources import SqlContinuousForwardSources
from packages.persistence.daily_runtime_risk import (
    ResolvedRuntimeRiskInputs,
    RuntimeReadBudget,
    capture_runtime_table,
    daily_attempt_inventory_sha256,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_admissions,
    daily_runtime_hold_heads,
)
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.schema import metadata
from tests.integration.test_personal_forward_capture_journal import capture, journal
from tests.integration.test_sql_account_coordinator import MutableClock
from tests.integration.test_sql_daily_runtime_risk import (
    Harness,
    RetainedFixtureReader,
    _write_transaction,
    fixture_meta,
    records,
    retain,
)
from tests.unit.test_continuous_engine import inputs_and_prices, start
from tests.unit.test_daily_risk_snapshot import runtime_case
from tests.unit.test_personal_forward_capture import Clock, Transport, daily_body, request


@dataclass(frozen=True, slots=True)
class SyntheticHistoricalClosure(ContractRecord):
    record_sha256: str
    names: tuple[tuple[str, str], ...]


class SyntheticHistoricalReader(RetainedFixtureReader):
    """Exact retained fixture role rows. This is not the production source port."""

    def __init__(self, account, artifacts):
        super().__init__(account)
        self.artifacts = artifacts
        self.seal = object()
        self.owned = WeakValueDictionary()
        self.resolve_hook = None

    def own(self, value):
        self.owned[id(value)] = value
        return value

    def require(self, value):
        assert self.owned.get(id(value)) is value and value.seal is self.seal

    def retain_admission_sources(self, view, *, snapshot):
        refs = view.resolved.inputs
        names = {"resolved-" + refs.semantic_sha256, *(s.semantic_sha256 for s in refs.sources)}
        rows = tuple(row for t in snapshot.tables for row in t.rows if row["name"] in names)
        assert len(rows) == len(names)
        closure = SyntheticHistoricalClosure(
            view.record_sha256, tuple(sorted((r["name"], r["digest"]) for r in rows))
        )
        return ContinuousEvidenceRef(
            "synthetic-runtime-closure/1",
            self.artifacts.put(codec.encode_record(closure)),
            closure.semantic_sha256,
        )

    def prepare_admission_source_read(self, reference, *, record_sha256, previous):
        assert previous is not None and previous.receipt.commit.scope.account_id == self.account
        assert reference.schema_id == "synthetic-runtime-closure/1"
        raw = self.artifacts.read(reference.object_ref)
        closure = codec.decode_record(raw, SyntheticHistoricalClosure)
        assert (
            codec.encode_record(closure) == raw
            and closure.semantic_sha256 == reference.semantic_sha256
        )
        assert closure.record_sha256 == record_sha256
        return self.own(ContinuousProducerPlan(reference, record_sha256, closure, self.seal))

    def capture_admission_sources_in_transaction(self, connection, plan):
        self.require(plan)
        table = capture_runtime_table(
            connection, records, account_id=self.account, budget=RuntimeReadBudget()
        )
        expected = dict(plan.state.names)
        selected = tuple(r for r in table.rows if r["name"] in expected)
        assert len(selected) == len(expected)
        assert all(r["digest"] == expected[r["name"]] for r in selected)
        return self.own(
            ContinuousProducerSnapshot(
                plan.reference, plan.record_sha256, replace(table, rows=selected), self.seal
            )
        )

    def resolve_admission_sources(self, snapshot, *, admission, previous):
        self.require(snapshot)
        if self.resolve_hook is not None:
            self.resolve_hook()
        assert previous is not None
        assert previous.checkpoint.inputs.spec.account_id == self.account
        rows = snapshot.state.rows
        by_name = {row["name"]: row for row in rows}
        expected = admission.resolved
        for name, kind, value in (
            ("resolved-" + expected.inputs.semantic_sha256, ResolvedRuntimeRiskInputs, expected),
            *((s.semantic_sha256, type(s), s) for s in expected.inputs.sources),
        ):
            row = by_name[name]
            assert sha256(row["payload"]).hexdigest() == row["digest"]
            actual = codec.decode_record(row["payload"], kind)
            assert actual == value and codec.encode_record(actual) == row["payload"]
        for source in expected.inputs.sources:
            assert source.value_sha256 == runtime_source_value_sha256(
                source.spec.role,
                expected.snapshot,
                admission.admission.decision.batch,
                expected.inputs,
            )
        return self.own(
            ResolvedContinuousProducerClosure(
                snapshot.reference, snapshot.record_sha256, snapshot.state, self.seal
            )
        )

    def recheck_admission_sources_in_transaction(self, connection, resolved):
        self.require(resolved)
        expected = resolved.state.rows
        actual = capture_runtime_table(
            connection, records, account_id=self.account, budget=RuntimeReadBudget()
        )
        names = {r["name"] for r in expected}
        assert tuple(r for r in actual.rows if r["name"] in names) == expected


class ActualDailyHarness(Harness):
    def __init__(self, engine, inputs):
        self.inputs, self.engine = inputs, engine
        self.account, self.decision_at = inputs.spec.account_id, inputs.spec.initialized_at
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
        from packages.persistence.daily_runtime_risk import SqlDailyRuntimeRisk

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
        initial = start(inputs)
        self.snapshot, self.state = initial.current.snapshot, initial.state
        self.base = runtime_case(now=self.decision_at)
        self.batch = self.base[2]
        self.producer_map = RuntimeProducerMap(
            producers=tuple(replace(p, account_scope=self.account) for p in self.base[4].producers)
        )
        self.assignment = replace(
            self.base[0],
            account_id=self.account,
            producer_map_sha256=self.producer_map.semantic_sha256,
            enabled_for_new_exposure=False,
        )
        self.install(self.assignment)

    def install(self, assignment):
        assignment = replace(
            assignment,
            account_binding_sha256=self.inputs.spec.account_binding_sha256,
            policy=self.inputs.spec.risk_policy,
            strategy=self.inputs.spec.strategy,
            configuration_sha256=content_digest(self.inputs.spec.strategy_configuration),
            effective_at=self.inputs.spec.initialized_at,
            instrument_symbols=self.inputs.spec.instruments,
        )
        super().install(assignment)


class RetainedEngineEvidence:
    def __init__(self, harness):
        self.h = harness
        self.values = {}

    def build(
        self,
        *,
        snapshot,
        batch,
        phase,
        evaluated_at,
        accepted_intent_ids,
        daily_return,
        drawdown,
        request_rows,
    ):
        h = self.h
        current = h.resolved()
        refs = runtime_case(snapshot=snapshot, batch=batch, phase=phase, now=evaluated_at)[3]
        heads = ReconciliationHeads(
            snapshot.journal_sha256,
            snapshot.order_sha256,
            current.obligations.semantic_sha256,
            0,
            daily_attempt_inventory_sha256(()),
            current.control.sequence_number,
            h.lease.fencing_generation,
        )
        refs = replace(
            refs,
            assignment_sha256=h.assignment.semantic_sha256,
            heads=heads,
            obligations=current.obligations,
            source_session=batch.target.trigger.source_session,
            execution_session=batch.target.trigger.execution_session,
            accepted_intent_ids=accepted_intent_ids,
            daily_return=daily_return,
            drawdown=drawdown,
            reconciliation=replace(
                refs.reconciliation,
                scope=replace(
                    refs.reconciliation.scope,
                    account_id=h.account,
                    binding_sha256=h.assignment.account_binding_sha256,
                ),
                heads=heads,
            ),
            sources=(),
        )
        original = runtime_case(snapshot=snapshot, batch=batch, phase=phase, now=evaluated_at)[
            3
        ].sources
        refs = replace(
            refs,
            sources=tuple(
                replace(
                    s,
                    spec=next(p for p in h.producer_map.producers if p.role == s.spec.role),
                    account_id=h.account,
                    account_binding_sha256=h.assignment.account_binding_sha256,
                    value_sha256=runtime_source_value_sha256(s.spec.role, snapshot, batch, refs),
                )
                for s in original
            ),
        )
        self.values[snapshot.semantic_sha256] = refs
        return build_daily_runtime_evidence(
            h.assignment,
            snapshot,
            batch,
            refs,
            producer_map=h.producer_map,
            evaluated_at=evaluated_at,
        )


class Case:
    def __init__(self, tmp_path, *, captured=True):
        self.engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/account.sqlite")
        self.inputs, self.prices = inputs_and_prices()
        self.h = ActualDailyHarness(self.engine, self.inputs)
        metadata.create_all(self.engine, tables=(*JOURNAL_TABLES, *CONTINUOUS_ACCOUNT_TABLES))
        self.artifacts = LocalResearchArtifactStore(tmp_path / "objects")
        self.reader = SyntheticHistoricalReader(self.h.account, self.artifacts)
        self.h.store.producers = self.reader
        self.h.reader = self.reader
        self.h.enable()
        self.evidence = RetainedEngineEvidence(self.h)
        self.owner = ContinuousAccountTransitionPreparer(
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(),
            runtime_evidence=self.evidence,
        )
        self.forward = SqlContinuousForwardSources(
            self.engine, artifacts=self.artifacts, codec=codec, evidence_class="synthetic_fixture"
        )
        self.publications = []
        template = request("daily")
        source = replace(template.source, account_scope=self.h.account)
        self.template = replace(
            template,
            source=source,
            instruments=(
                replace(template.instruments[0], instrument_id=self.inputs.spec.instruments[0][0]),
            ),
            journal_key=replace(
                template.journal_key,
                account_scope=self.h.account,
                source_scope_sha256=source.semantic_sha256,
            ),
        )
        self.initial_source = ForwardDataState((source,), "recorded")
        self.source_state = self.initial_source
        if captured:
            for session in self.inputs.spec.window.warmup_sessions:
                self.add_capture(session)
            closure = self.closure("bootstrap", self.inputs.spec.initialized_at)
            self.inputs = compile_continuous_bootstrap(
                self.inputs.spec,
                self.source_state,
                closure.observation_ids,
                closure.admitted_at,
                benchmark_instrument_id=self.inputs.spec.instruments[0][0],
                capture_evidence_class=closure.evidence_class,
            )
            self.initial_ref = self.put(FORWARD_CLOSURE_SCHEMA, closure)
            closure_sha = closure.semantic_sha256
        else:
            source = SyntheticContinuousBootstrap(self.inputs)
            self.initial_ref = self.put(SYNTHETIC_BOOTSTRAP_SCHEMA, source)
            closure_sha = source.semantic_sha256
        self.first = self.owner.prepare_initialize(
            command_id="initialize", inputs=self.inputs, source_closure_sha256=closure_sha
        )
        self.scope = ContinuousAccountScope(
            self.h.account, self.inputs.spec.account_binding_sha256, self.inputs.spec.deployment_id
        )
        self.store = self.new_store()

    def put(self, schema, value):
        return ContinuousEvidenceRef(
            schema, self.artifacts.put(codec.encode_record(value)), value.semantic_sha256
        )

    def add_capture(self, session):
        calendar = next(s for s in self.inputs.spec.calendar.sessions if s.session_label == session)
        req = replace(
            self.template,
            capture_id="daily-" + session.isoformat(),
            session=session,
            session_open=calendar.opens_at,
            session_close=calendar.closes_at,
            window_start=calendar.opens_at,
            window_end=calendar.closes_at + timedelta(minutes=5),
        )
        publication = capture(
            req,
            self.source_state,
            journal(self.engine),
            self.artifacts,
            clock=Clock(calendar.closes_at + timedelta(seconds=1)),
            transport=Transport(
                daily_body(
                    date=session.isoformat() + "T00:00:00.000Z",
                    open=100,
                    high=101,
                    low=99,
                    close=100,
                    adjOpen=100,
                    adjHigh=101,
                    adjLow=99,
                    adjClose=100,
                )
            ),
            head=None
            if not self.publications
            else self.publications[-1].journal_receipt.committed_head,
        )
        self.publications.append(publication)
        self.source_state = replay_capture(
            publication.record, self.source_state, artifacts=self.artifacts
        )
        return publication

    def closure(self, identity, at, selected=None):
        return ContinuousForwardClosure(
            account_id=self.h.account,
            closure_id=identity,
            initial_state=self.initial_source,
            publications=tuple(self.publications),
            observation_ids=tuple(
                sorted(selected or tuple(o.observation_id for o in self.source_state.observations))
            ),
            admitted_at=at,
            evidence_class="synthetic_fixture",
        )

    def new_store(self):
        self.composer = SqlContinuousCommitComposer(
            self.engine,
            daily=self.h.store,
            coordinator=self.h.coordinator,
            forward_sources=self.forward,
            artifacts=self.artifacts,
            codec=codec,
            producer_history=self.reader,
            fence=self.h.lease.fence,
            benchmark_instrument_id=self.inputs.spec.instruments[0][0],
        )
        return SqlContinuousAccount(
            self.engine,
            coordinator=self.h.coordinator,
            journal=SqlDurableJournal(
                self.engine,
                codec=codec,
                record_types={CONTINUOUS_COMMIT_SCHEMA: ContinuousAccountCommit},
            ),
            artifacts=self.artifacts,
            codec=codec,
            preparer=self.owner,
            composer=self.composer,
        )

    def publish(self, transition=None, previous=None, ref=None, admissions=()):
        prepared = self.store.prepare(
            transition or self.first,
            scope=self.scope,
            previous=previous,
            source_evidence=ref or self.initial_ref,
            admissions=admissions,
        )
        with self.store.write_transaction() as connection:
            receipt = self.store.commit_in_transaction(
                connection, prepared=prepared, fence=self.h.lease.fence
            )
        return receipt

    def next(self):
        session = self.inputs.spec.window.scored_sessions[0]
        publication = self.add_capture(session)
        at = modeled_daily_availability(session) + timedelta(milliseconds=50)
        self.h.coordinator.release(self.h.lease.fence)
        self.h.clock.instant = at
        self.h.decision_at = at
        self.h.lease = self.h.coordinator.acquire("owner")
        self.store = self.new_store()
        previous = self.store.restore(self.scope)
        closure = self.closure(
            "first-close", at, tuple(o.observation_id for o in publication.record.observations)
        )
        frontier = project_continuous_daily_frontier(
            checkpoint=previous.checkpoint,
            source_state=self.source_state,
            observation_ids=closure.observation_ids,
            frontier_id=closure.closure_id,
            admitted_at=at,
            benchmark_instrument_id=self.inputs.spec.instruments[0][0],
            capture_evidence_class=closure.evidence_class,
        )
        transition = self.owner.prepare_frontier(
            command_id="first-close", checkpoint=previous.checkpoint, frontier=frontier
        )
        admissions = []
        for index, decision in enumerate(transition.new_decisions):
            refs = self.evidence.values[decision.snapshot.semantic_sha256]
            resolved = ResolvedRuntimeRiskInputs(
                decision.source_state,
                decision.snapshot,
                refs,
                self.h.producer_map,
                decision.source_context,
                self.inputs.spec.execution_policy,
            )
            with _write_transaction(self.engine) as connection:
                retain(connection, self.h.account, "resolved-" + refs.semantic_sha256, resolved)
                for source in refs.sources:
                    retain(connection, self.h.account, source.semantic_sha256, source)
            admissions.append(
                self.h.prepare(
                    dict(
                        command_id=f"actual-admission-{index}",
                        request_sha256=decision.batch.semantic_sha256,
                        batch=decision.batch,
                        assignment_sha256=self.h.assignment.semantic_sha256,
                        input_refs=refs,
                        prepared_commitments=decision.installed_commitments,
                        fence=self.h.lease.fence,
                    )
                )
            )
        return previous, transition, self.put(FORWARD_CLOSURE_SCHEMA, closure), tuple(admissions)


@pytest.fixture
def case(tmp_path):
    value = Case(tmp_path)
    yield value
    value.engine.dispose()


@pytest.mark.parametrize("captured", [False, True])
def test_actual_initialization_uses_retained_source_and_restarts(tmp_path, captured):
    case = Case(tmp_path, captured=captured)
    try:
        receipt = case.publish()
        restarted = case.new_store()
        resolved = restarted.restore(case.scope)
        assert resolved.receipt == receipt and resolved.checkpoint == case.first.checkpoint
        assert not resolved.checkpoint.runtime_decisions
        with restarted.write_transaction() as connection:
            assert (
                restarted.retry_in_transaction(
                    connection,
                    original=resolved,
                    command_sha256=case.first.command_sha256,
                    fence=case.h.lease.fence,
                )
                == receipt
            )
    finally:
        case.engine.dispose()


def test_actual_engine_admission_hold_and_checkpoint_publish_atomically_and_restore(case):
    initial = case.publish()
    previous, transition, ref, admissions = case.next()
    assert len(transition.new_decisions) == len(admissions) == 1
    assert transition.new_decisions[0].installed_commitments
    receipt = case.publish(transition, previous, ref, admissions)
    assert receipt.commit.sequence == initial.commit.sequence + 1
    with case.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_admissions)) == 1
        )
        assert connection.scalar(
            sa.select(sa.func.count()).select_from(daily_runtime_hold_heads)
        ) == len(transition.new_decisions[0].installed_commitments)
    restored = case.new_store().restore(case.scope)
    assert restored.checkpoint == transition.checkpoint and restored.receipt == receipt
    binding = restored.composition.state.evidence.after_obligations.bindings[0]
    assert (
        binding.source_sha256
        == case.h.store.inspect_prepared_admission(admissions[0]).record_sha256
    )
    assert binding.source_sha256 != admissions[0].result.semantic_sha256


@pytest.mark.parametrize("change", ["missing", "duplicate", "copied"])
def test_actual_decision_cannot_publish_without_one_exact_owned_admission(case, change):
    case.publish()
    previous, transition, ref, admissions = case.next()
    selected = (
        ()
        if change == "missing"
        else (admissions * 2 if change == "duplicate" else (replace(admissions[0]),))
    )
    with pytest.raises(ValueError):
        case.publish(transition, previous, ref, selected)
    with case.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(continuous_account_commits))
            == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_admissions)) == 0
        )


@pytest.mark.parametrize("changed", ["source", "control", "journal_failure"])
def test_final_failure_rolls_back_actual_admission_holds_and_checkpoint(case, monkeypatch, changed):
    case.publish()
    previous, transition, ref, admissions = case.next()
    prepared = case.store.prepare(
        transition, scope=case.scope, previous=previous, source_evidence=ref, admissions=admissions
    )
    if changed == "source":
        with case.engine.begin() as connection:
            connection.execute(
                sa.update(journal_entries)
                .where(journal_entries.c.command_id.like("daily-%"))
                .values(payload=b"{}")
            )
    elif changed == "control":
        case.h.controls.apply(
            case.h.command(
                OperationalControlCommandKind.HALT, "later-halt", OperationalControlState.HALTED
            )
        )
    else:

        def fail(*args, **kwargs):
            raise ValueError("TEST_ATOMIC_JOURNAL_FAILURE")

        monkeypatch.setattr(case.store.journal, "append_in_transaction", fail)
    with case.store.write_transaction() as connection, pytest.raises(ValueError):
        case.store.commit_in_transaction(connection, prepared=prepared, fence=case.h.lease.fence)
    with case.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(continuous_account_commits))
            == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_admissions)) == 0
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_hold_heads)) == 0
        )


def test_no_codec_source_read_or_financial_replay_inside_atomic_publication(case, monkeypatch):
    case.publish()
    previous, transition, ref, admissions = case.next()
    prepared = case.store.prepare(
        transition, scope=case.scope, previous=previous, source_evidence=ref, admissions=admissions
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("DETACHED_WORK_INSIDE_SQL")

    monkeypatch.setattr(codec, "encode_record", forbidden)
    monkeypatch.setattr(codec, "decode_record", forbidden)
    monkeypatch.setattr(case.artifacts, "read", forbidden)
    monkeypatch.setattr(case.artifacts, "put", forbidden)
    monkeypatch.setattr(PersonalAccounting, "project", forbidden)
    monkeypatch.setattr(PersonalAccounting, "advance", forbidden)
    with case.store.write_transaction() as connection:
        receipt = case.store.commit_in_transaction(
            connection, prepared=prepared, fence=case.h.lease.fence
        )
    assert receipt.commit.sequence == 2


def test_restored_original_admission_allows_later_control_head_and_inert_retry(case):
    case.publish()
    previous, transition, ref, admissions = case.next()
    receipt = case.publish(transition, previous, ref, admissions)
    case.h.controls.apply(
        case.h.command(
            OperationalControlCommandKind.HALT, "later-halt", OperationalControlState.HALTED
        )
    )
    case.store = case.new_store()
    resolved = case.store.restore(case.scope)
    assert resolved.receipt == receipt and resolved.checkpoint == transition.checkpoint
    with case.store.write_transaction() as connection:
        assert (
            case.store.retry_in_transaction(
                connection,
                original=resolved,
                command_sha256=transition.command_sha256,
                fence=case.h.lease.fence,
            )
            == receipt
        )
    with case.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_admissions)) == 1
        )


def test_historical_producer_role_row_tamper_rejects_fresh_restore(case):
    case.publish()
    previous, transition, ref, admissions = case.next()
    case.publish(transition, previous, ref, admissions)
    source = admissions[0].result.evidence.inputs.sources[0]
    with case.engine.begin() as connection:
        connection.execute(
            sa.update(records).where(records.c.name == source.semantic_sha256).values(payload=b"{}")
        )
    with pytest.raises((ValueError, AssertionError)):
        case.new_store().restore(case.scope)


def test_historical_raw_capture_recheck_detects_changed_source_after_detached_replay(case):
    case.publish()
    previous, transition, ref, admissions = case.next()
    case.publish(transition, previous, ref, admissions)
    resolved = case.store.restore(case.scope)
    source = admissions[0].result.evidence.inputs.sources[0]
    with case.engine.begin() as connection:
        connection.execute(
            sa.update(records).where(records.c.name == source.semantic_sha256).values(payload=b"{}")
        )
    with case.store.write_transaction() as connection, pytest.raises((ValueError, AssertionError)):
        case.store.retry_in_transaction(
            connection,
            original=resolved,
            command_sha256=transition.command_sha256,
            fence=case.h.lease.fence,
        )


def test_copied_composer_tokens_and_missing_historical_port_are_not_authority(case):
    prepared = case.store.prepare(
        case.first, scope=case.scope, previous=None, source_evidence=case.initial_ref
    )
    with pytest.raises(ContinuousCompositionError, match="OWNED"):
        case.composer.require_prepared(replace(prepared.composition))
    with pytest.raises(ContinuousCompositionError, match="DEPENDENCIES"):
        SqlContinuousCommitComposer(
            case.engine,
            daily=case.h.store,
            coordinator=case.h.coordinator,
            forward_sources=case.forward,
            artifacts=case.artifacts,
            codec=codec,
            producer_history=RetainedFixtureReader(case.h.account),
            fence=case.h.lease.fence,
            benchmark_instrument_id=case.inputs.spec.instruments[0][0],
        )


@pytest.mark.parametrize("delay", ["equal", "after"])
def test_deadline_crossed_after_b_admit_rolls_back_entire_publication(case, monkeypatch, delay):
    case.publish()
    previous, transition, ref, admissions = case.next()
    prepared = case.store.prepare(
        transition, scope=case.scope, previous=previous, source_evidence=ref, admissions=admissions
    )
    deadline = admissions[0].valid_until
    assert prepared.composition.valid_until == deadline
    original = case.store.journal.append_in_transaction

    def delayed(connection, append):
        result = original(connection, append)
        # Actual B writes already exist in this same caller-owned transaction.
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_admissions)) == 1
        )
        case.h.clock.instant = deadline + (
            timedelta(microseconds=1) if delay == "after" else timedelta()
        )
        return result

    monkeypatch.setattr(case.store.journal, "append_in_transaction", delayed)
    with (
        case.store.write_transaction() as connection,
        pytest.raises(ValueError, match="DEADLINE_EXPIRED"),
    ):
        case.store.commit_in_transaction(connection, prepared=prepared, fence=case.h.lease.fence)
    with case.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_admissions)) == 0
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_hold_heads)) == 0
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(continuous_account_commits))
            == 1
        )


def test_stalled_detached_producer_resolution_allows_actual_control_writer_commit(case):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    case.publish()
    previous, transition, ref, admissions = case.next()
    receipt = case.publish(transition, previous, ref, admissions)
    started, proceed = Event(), Event()

    def stalled():
        started.set()
        assert proceed.wait(5)

    case.reader.resolve_hook = stalled
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(case.store.restore, case.scope)
        try:
            assert started.wait(5)
            control = case.h.controls.apply(
                case.h.command(
                    OperationalControlCommandKind.HALT,
                    "while-decoding",
                    OperationalControlState.HALTED,
                )
            )
            assert control.effective_state == OperationalControlState.HALTED
        finally:
            proceed.set()
        assert future.result(timeout=5).receipt == receipt


def test_same_instance_composition_mutation_is_rejected(case):
    prepared = case.store.prepare(
        case.first, scope=case.scope, previous=None, source_evidence=case.initial_ref
    )
    object.__setattr__(prepared.composition.state.sources, "captured", None)
    with pytest.raises(ContinuousCompositionError, match="STATE_CHANGED"):
        case.composer.require_prepared(prepared.composition)


@pytest.mark.parametrize("delay", ["equal", "after"])
def test_outer_commit_deadline_after_successful_c_commit_rolls_back_all_actual_b_writes(
    case, delay
):
    case.publish()
    previous, transition, ref, admissions = case.next()
    prepared = case.store.prepare(
        transition, scope=case.scope, previous=previous, source_evidence=ref, admissions=admissions
    )
    before = case.h.counts()
    deadline = admissions[0].valid_until
    with (
        pytest.raises(ValueError, match="DEADLINE_EXPIRED"),
        case.store.write_transaction() as connection,
    ):
        receipt = case.store.commit_in_transaction(
            connection, prepared=prepared, fence=case.h.lease.fence
        )
        result = case.store.require_committed_in_transaction(
            connection, prepared=prepared, receipt=receipt
        )
        assert result.row["commit_sha256"] == receipt.commit.semantic_sha256
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_admissions)) == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_hold_heads)) > 0
        )
        # C has returned successfully. Later coupled work delays only the owning
        # outer COMMIT; this must still reject equality with the original deadline.
        case.h.clock.instant = deadline + (
            timedelta(microseconds=1) if delay == "after" else timedelta()
        )
    assert case.h.counts() == before
    assert not case.store._pending_publications
    with case.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(continuous_account_commits))
            == 1
        )
    assert case.new_store().restore(case.scope).receipt == previous.receipt
