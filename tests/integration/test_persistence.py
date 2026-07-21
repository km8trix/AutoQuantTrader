from dataclasses import replace
from datetime import datetime
from decimal import Decimal, localcontext

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError

from apps.api.config import Settings
from apps.api.main import create_app
from packages.domain.clock import FixedClock
from packages.domain.models import DecisionStatus, OrderIntent, RiskDecision
from packages.domain.risk import (
    FixedRiskAccountSnapshotProvider,
    RiskAccountSnapshot,
    RiskAuthority,
    RiskAuthorizationError,
    RiskDecisionRepository,
    RiskLimits,
)
from packages.domain.walking_thread import WalkingThread
from packages.persistence.database import create_database_engine
from packages.persistence.immutable import ImmutableFactConflict, insert_or_verify
from packages.persistence.risk import SqlRiskDecisionRepository
from packages.persistence.schema import (
    fills,
    ledger_entries,
    ledger_postings,
    orders,
    phase2_batch_members,
    risk_account_guards,
    risk_decisions,
    risk_reservations,
    submission_attempts,
)
from packages.persistence.walking_thread import (
    WalkingThreadUnitOfWork,
    initialize_phase_zero_schema,
)


def row_count(engine: Engine, table: sa.Table) -> int:
    with engine.connect() as connection:
        return int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0)


def sql_repository(engine: Engine) -> SqlRiskDecisionRepository:
    return SqlRiskDecisionRepository(engine, WalkingThread.risk_authority())


def test_startup_persists_every_fact_and_duplicate_startup_is_idempotent() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")

    first = create_app(Settings(), engine=engine)
    second = create_app(Settings(), engine=engine)

    assert first.state.persistence_status == "ephemeral"
    assert second.state.persistence_status == "ephemeral"
    assert row_count(engine, risk_account_guards) == 1
    assert row_count(engine, risk_decisions) == 1
    assert row_count(engine, risk_reservations) == 1
    assert row_count(engine, submission_attempts) == 1
    assert row_count(engine, orders) == 1
    assert row_count(engine, fills) == 1
    assert row_count(engine, ledger_entries) == 2
    assert row_count(engine, ledger_postings) == 5
    with engine.connect() as connection:
        attempt = connection.execute(sa.select(submission_attempts)).mappings().one()
        persisted_order_id = connection.scalar(sa.select(orders.c.order_id))
    assert attempt["state"] == "recorded"
    assert attempt["order_id"] == persisted_order_id


def test_sqlite_engine_enforces_phase2_foreign_keys() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    initialize_phase_zero_schema(engine)

    with engine.connect() as connection:
        assert connection.scalar(sa.text("PRAGMA foreign_keys")) == 1

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_batch_members).values(
                membership_id="orphan-phase2-batch-member",
                decision_id="missing-phase2-batch-decision",
                intent_batch_id="orphan-intent-batch",
                intent_batch_sha256="a" * 64,
                ordinal=0,
                intent_id="orphan-phase2-intent",
                intent_payload_sha256="b" * 64,
                canonical_payload="{}",
                semantic_sha256="c" * 64,
            )
        )


class CommitOrderSpy(RiskDecisionRepository):
    def __init__(self, delegate: SqlRiskDecisionRepository, engine: Engine) -> None:
        self.delegate = delegate
        self.engine = engine
        self.saw_committed_decision_before_submit = False

    def authorize(self, intent: OrderIntent) -> RiskDecision:
        return self.delegate.authorize(intent)

    def get(self, decision_id: str) -> RiskDecision | None:
        return self.delegate.get(decision_id)

    def consume(self, decision_id: str, intent: OrderIntent) -> datetime:
        with self.engine.connect() as connection:
            decision_row = (
                connection.execute(
                    sa.select(risk_decisions).where(risk_decisions.c.decision_id == decision_id)
                )
                .mappings()
                .one()
            )
            reservation_row = (
                connection.execute(
                    sa.select(risk_reservations).where(
                        risk_reservations.c.decision_id == decision_id
                    )
                )
                .mappings()
                .one()
            )
        self.saw_committed_decision_before_submit = (
            decision_row["consumed_at"] is None and reservation_row["state"] == "approved"
        )
        return self.delegate.consume(decision_id, intent)


def test_risk_decision_is_committed_before_simulated_submit_and_is_single_use() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    initialize_phase_zero_schema(engine)
    repository = sql_repository(engine)
    spy = CommitOrderSpy(repository, engine)

    result = WalkingThread.run(spy)

    assert spy.saw_committed_decision_before_submit is True
    with engine.connect() as connection:
        attempt = connection.execute(sa.select(submission_attempts)).mappings().one()
    assert attempt["decision_id"] == result.risk_decision.decision_id
    assert attempt["intent_id"] == result.intent.intent_id
    assert attempt["submitted_at"] == result.order.submitted_at.replace(tzinfo=None)
    assert attempt["state"] == "authorized"
    assert attempt["order_id"] is None
    with pytest.raises(RiskAuthorizationError, match="already been consumed"):
        repository.consume(
            result.risk_decision.decision_id,
            result.intent,
        )


def test_unit_of_work_rolls_back_all_new_facts_on_immutable_conflict() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    initialize_phase_zero_schema(engine)
    result = WalkingThread.run(sql_repository(engine))
    with engine.begin() as connection:
        connection.execute(
            sa.insert(ledger_entries).values(
                entry_id=result.ledger_entries[0].entry_id,
                event_type="forged",
                reference_id="forged",
                posted_at=result.started_at,
            )
        )

    with pytest.raises(ImmutableFactConflict):
        WalkingThreadUnitOfWork(engine).persist(result)

    assert row_count(engine, risk_account_guards) == 1
    assert row_count(engine, risk_decisions) == 1
    assert row_count(engine, risk_reservations) == 1
    assert row_count(engine, submission_attempts) == 1
    assert row_count(engine, orders) == 0
    assert row_count(engine, fills) == 0
    assert row_count(engine, ledger_entries) == 1
    assert row_count(engine, ledger_postings) == 0
    with engine.connect() as connection:
        attempt = connection.execute(sa.select(submission_attempts)).mappings().one()
    assert attempt["state"] == "authorized"
    assert attempt["order_id"] is None


def test_database_rejects_fractional_persisted_order_quantity() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    create_app(Settings(), engine=engine)

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(sa.update(orders).values(quantity=sa.literal(10.5)))


def test_immutable_conflict_is_reported_as_not_ready() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    create_app(Settings(), engine=engine)
    with engine.begin() as connection:
        connection.execute(sa.update(risk_decisions).values(status="rejected"))

    app = create_app(Settings(), engine=engine)
    client = TestClient(app)

    assert app.state.persistence_status == "unavailable"
    assert client.get("/health/ready").status_code == 503
    trace = client.get("/api/v1/walking-thread/trace").json()
    assert trace["risk_decision"]["persisted"] is False
    assert trace["risk_decision"]["persistence_mode"] == "unavailable"


def test_sql_reservations_prevent_double_spending() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    initialize_phase_zero_schema(engine)
    result = WalkingThread.run()
    snapshot = RiskAccountSnapshot(
        account_id="constrained-account",
        version="cash-v1",
        available_cash=Decimal("1500"),
    )
    limits = RiskLimits(
        allowed_instruments=frozenset({WalkingThread.instrument_id}),
        max_order_quantity=Decimal("100"),
        max_order_notional=Decimal("25000"),
        minimum_cash_buffer=Decimal("0"),
    )
    authority = RiskAuthority(
        limits=limits,
        account_snapshots=FixedRiskAccountSnapshotProvider(snapshot),
        evaluation_clock=FixedClock(result.risk_decision.evaluated_at),
        consumption_clock=FixedClock(result.order.submitted_at),
    )
    repository = SqlRiskDecisionRepository(engine, authority)
    first = repository.authorize(result.intent)
    second_intent = replace(
        result.intent,
        intent_id="sql-competing-intent",
        target_id="sql-competing-target",
    )
    second = repository.authorize(second_intent)

    assert not hasattr(repository, "save")
    assert first.status is DecisionStatus.APPROVED
    assert second.status is DecisionStatus.REJECTED
    with engine.connect() as connection:
        reserved = connection.scalar(
            sa.select(risk_account_guards.c.reserved_cash).where(
                risk_account_guards.c.account_id == snapshot.account_id
            )
        )
    assert Decimal(str(reserved)) == Decimal("1001.00")
    assert row_count(engine, risk_reservations) == 1


def test_sql_sequential_reservations_ignore_ambient_decimal_context() -> None:
    result = WalkingThread.run()
    first_intent = replace(
        result.intent,
        intent_id="sql-decimal-context-first",
        target_id="sql-decimal-context-first-target",
        quantity=Decimal("3"),
        reference_price=Decimal("1.23456789"),
    )
    second_intent = replace(
        first_intent,
        intent_id="sql-decimal-context-second",
        target_id="sql-decimal-context-second-target",
    )
    snapshot = RiskAccountSnapshot(
        account_id="sql-decimal-context-account",
        version="sql-decimal-context-v1",
        available_cash=Decimal("7.40740734"),
    )
    limits = RiskLimits(
        allowed_instruments=frozenset({result.intent.instrument_id}),
        max_order_quantity=Decimal("100"),
        max_order_notional=Decimal("10"),
        minimum_cash_buffer=Decimal("0"),
        estimated_fee=Decimal("0"),
    )

    def authorize(precision: int) -> tuple[DecisionStatus, DecisionStatus, Decimal]:
        engine = create_database_engine("sqlite+pysqlite:///:memory:")
        initialize_phase_zero_schema(engine)
        authority = RiskAuthority(
            limits=limits,
            account_snapshots=FixedRiskAccountSnapshotProvider(snapshot),
            evaluation_clock=FixedClock(result.risk_decision.evaluated_at),
            consumption_clock=FixedClock(result.order.submitted_at),
        )
        repository = SqlRiskDecisionRepository(engine, authority)
        with localcontext() as context:
            context.prec = precision
            first = repository.authorize(first_intent)
            second = repository.authorize(second_intent)
        with engine.connect() as connection:
            reserved = connection.scalar(
                sa.select(risk_account_guards.c.reserved_cash).where(
                    risk_account_guards.c.account_id == snapshot.account_id
                )
            )
        assert reserved is not None
        return first.status, second.status, Decimal(str(reserved))

    low_precision = authorize(4)
    high_precision = authorize(40)

    assert low_precision == high_precision
    assert low_precision == (
        DecisionStatus.APPROVED,
        DecisionStatus.APPROVED,
        Decimal("7.4074073400"),
    )


def test_sql_authorization_rolls_back_lossy_decimal_storage() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    initialize_phase_zero_schema(engine)
    result = WalkingThread.run()
    intent = replace(
        result.intent,
        intent_id="sql-lossy-decimal-intent",
        target_id="sql-lossy-decimal-target",
        quantity=Decimal("1"),
        reference_price=Decimal("123456789.1234567810"),
    )
    snapshot = RiskAccountSnapshot(
        account_id="sql-lossy-decimal-account",
        version="sql-lossy-decimal-v1",
        available_cash=Decimal("500000000"),
    )
    authority = RiskAuthority(
        limits=RiskLimits(
            allowed_instruments=frozenset({intent.instrument_id}),
            max_order_quantity=Decimal("100"),
            max_order_notional=Decimal("200000000"),
            minimum_cash_buffer=Decimal("0"),
            estimated_fee=Decimal("0"),
        ),
        account_snapshots=FixedRiskAccountSnapshotProvider(snapshot),
        evaluation_clock=FixedClock(result.risk_decision.evaluated_at),
        consumption_clock=FixedClock(result.order.submitted_at),
    )

    with pytest.raises(RiskAuthorizationError, match="exact risk authorization"):
        SqlRiskDecisionRepository(engine, authority).authorize(intent)

    assert row_count(engine, risk_account_guards) == 0
    assert row_count(engine, risk_decisions) == 0
    assert row_count(engine, risk_reservations) == 0


def test_first_immutable_insert_rolls_back_lossy_decimal_storage() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    metadata = sa.MetaData()
    facts = sa.Table(
        "exact_numeric_facts",
        metadata,
        sa.Column("fact_id", sa.String(36), primary_key=True),
        sa.Column("amount", sa.Numeric(28, 10), nullable=False),
    )
    metadata.create_all(engine)

    with pytest.raises(ImmutableFactConflict, match="amount"), engine.begin() as connection:
        insert_or_verify(
            connection,
            facts,
            "fact_id",
            {
                "fact_id": "lossy-first-write",
                "amount": Decimal("123456789.1234567810"),
            },
        )

    assert row_count(engine, facts) == 0


@pytest.mark.parametrize(
    "malformed_rules",
    [
        "not-an-array",
        ["not-an-object"],
        [{"rule": "instrument_allow_list", "passed": True, "observed": "SPY"}],
        [
            {
                "rule": "instrument_allow_list",
                "passed": "false",
                "observed": "SPY",
                "limit": "SPY",
            }
        ],
        [
            {
                "rule": "instrument_allow_list",
                "passed": True,
                "observed": "SPY",
                "limit": "SPY",
                "extra": "forged",
            }
        ],
    ],
)
def test_sql_repository_rejects_malformed_persisted_rule_json(
    malformed_rules: object,
) -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    create_app(Settings(), engine=engine)
    result = WalkingThread.run()
    with engine.begin() as connection:
        connection.execute(
            sa.update(risk_decisions)
            .where(risk_decisions.c.decision_id == result.risk_decision.decision_id)
            .values(rules=malformed_rules)
        )

    with pytest.raises(RiskAuthorizationError, match="persisted risk"):
        sql_repository(engine).get(result.risk_decision.decision_id)
