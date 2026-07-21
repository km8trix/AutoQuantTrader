from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import TypeVar

import pytest
import sqlalchemy as sa

from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    AccountLeasePolicy,
    _account_fence_receipt,
)
from packages.domain.batch_risk import (
    ActiveCapacityReservationState,
    BatchRiskAuthority,
    BatchRiskDecisionStatus,
    BatchRiskFactConflict,
    VersionedBatchRiskSnapshot,
)
from packages.domain.models import OrderIntentBatch, TargetPortfolio
from packages.execution.account_coordinator import InMemoryAccountCoordinatorAuthority
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.batch_risk import (
    LEGACY_CAPACITY_OBSERVATION_CONTRACT,
    SqlBatchRiskRepository,
    _active_capacity_payload,
    _decision_fact_payload,
    _decode_active_capacity,
    load_batch_risk_decision,
)
from packages.persistence.database import (
    _verify_phase2_durability_integrity,
    create_database_engine,
)
from packages.persistence.reservation_lifecycle import SqlReservationLifecycleRepository
from packages.persistence.schema import (
    metadata,
    phase2_batch_authorizations,
    phase2_batch_decisions,
    phase2_batch_members,
    phase2_batch_reservations,
    phase2_reservation_release_events,
)
from tests.unit.test_batch_risk import (
    CONSUMED_AT,
    EVALUATED_AT,
    MutableClock,
    limits,
    make_batch,
    make_portfolio,
    mixed_case,
    snapshot,
)

ResultT = TypeVar("ResultT")


@dataclass(frozen=True)
class SnapshotTransactions:
    snapshot: VersionedBatchRiskSnapshot

    def current(self) -> VersionedBatchRiskSnapshot:
        return self.snapshot

    def transact(
        self,
        operation: Callable[[VersionedBatchRiskSnapshot], ResultT],
    ) -> ResultT:
        return operation(self.snapshot)


def _engine(path: Path) -> sa.Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    return engine


def _coordinator(
    engine: sa.Engine,
    *,
    clock: MutableClock,
    account_id: str,
) -> SqlAccountCoordinator:
    policy = AccountLeasePolicy(
        policy_id="phase2-sql-test-coordinator",
        policy_version="1.0.0",
        lease_ttl=timedelta(minutes=5),
        maximum_in_flight_duration=timedelta(seconds=5),
        takeover_safety_interval=timedelta(seconds=10),
    )
    authority = SqlAccountCoordinatorAuthority(
        engine=engine,
        policy=policy,
        clock=clock,
    )
    return SqlAccountCoordinator(account_id=account_id, authority=authority)


def _repository(
    engine: sa.Engine,
    capacity: VersionedBatchRiskSnapshot,
    coordinator: SqlAccountCoordinator,
    evaluation_clock: MutableClock,
) -> SqlBatchRiskRepository:
    authority = BatchRiskAuthority(
        limits=limits(),
        snapshots=SnapshotTransactions(capacity),
        evaluation_clock=evaluation_clock,
        consumption_clock=MutableClock(CONSUMED_AT),
    )
    return SqlBatchRiskRepository(
        engine=engine,
        authority=authority,
        coordinator=coordinator,
    )


def _rewrite_capacity_facts_as_legacy(engine: sa.Engine) -> None:
    """Model the 0009 backfill without changing immutable v3 decision payloads."""

    with engine.connect() as connection:
        rows = tuple(
            connection.execute(
                sa.select(phase2_batch_decisions).order_by(
                    phase2_batch_decisions.c.account_observation_sequence
                )
            ).mappings()
        )
        legacy_payloads: dict[str, str] = {}
        for row in rows:
            decision_id = str(row["decision_id"])
            decision = load_batch_risk_decision(connection, decision_id)
            assert decision is not None
            legacy_payloads[decision_id] = _decision_fact_payload(
                decision,
                _decode_active_capacity(row["active_capacity_payload"]),
                int(row["account_observation_sequence"]),
                capacity_observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
                fencing_generation=int(row["fencing_generation"]),
                lease_sha256=str(row["lease_sha256"]),
                fence_sha256=str(row["fence_sha256"]),
            )
    with engine.begin() as connection:
        for decision_id, canonical_payload in legacy_payloads.items():
            connection.execute(
                sa.update(phase2_batch_decisions)
                .where(phase2_batch_decisions.c.decision_id == decision_id)
                .values(
                    capacity_observation_contract=(LEGACY_CAPACITY_OBSERVATION_CONTRACT),
                    canonical_payload=canonical_payload,
                )
            )
        connection.execute(
            sa.update(phase2_reservation_release_events).values(
                visible_after_observation_sequence=0,
                capacity_visibility_sha256=None,
            )
        )


def test_approval_persists_parent_reservation_and_children_atomically(
    tmp_path: Path,
) -> None:
    _, target, batch, capacity = mixed_case()
    engine = _engine(tmp_path / "phase2-batch.sqlite")
    coordinator_clock = MutableClock(EVALUATED_AT)
    coordinator = _coordinator(
        engine,
        clock=coordinator_clock,
        account_id=capacity.account_id,
    )
    lease = coordinator.acquire("worker-a")
    risk = _repository(
        engine,
        capacity,
        coordinator,
        MutableClock(EVALUATED_AT),
    )

    decision = risk.authorize(batch, target, lease.fence)

    assert decision.status is BatchRiskDecisionStatus.APPROVED
    assert risk.get_batch(decision.decision_id) == decision
    assert risk.decision_for_batch(batch.intent_batch_id) == decision
    assert risk.active_reservations(capacity.account_id) == (decision.reservation,)
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_decisions)) == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_reservations))
            == 1
        )
        assert connection.scalar(
            sa.select(sa.func.count()).select_from(phase2_batch_authorizations)
        ) == len(batch.intents)
        row = connection.execute(sa.select(phase2_batch_decisions)).mappings().one()
        assert row["fencing_generation"] == lease.fencing_generation
        assert row["fence_sha256"] == lease.fence.semantic_sha256
        assert row["lease_sha256"] == lease.semantic_sha256
        assert row["account_observation_sequence"] == 1


def test_exact_retry_returns_original_without_duplicate_capacity(tmp_path: Path) -> None:
    _, target, batch, capacity = mixed_case()
    engine = _engine(tmp_path / "phase2-retry.sqlite")
    clock = MutableClock(EVALUATED_AT)
    coordinator = _coordinator(engine, clock=clock, account_id=capacity.account_id)
    lease = coordinator.acquire("worker-a")
    evaluation_clock = MutableClock(EVALUATED_AT)
    risk = _repository(engine, capacity, coordinator, evaluation_clock)
    original = risk.authorize(batch, target, lease.fence)
    clock.instant += timedelta(seconds=1)
    evaluation_clock.instant += timedelta(seconds=1)
    assert (
        risk.active_capacity(capacity.account_id).semantic_sha256 != original.active_capacity_sha256
    )

    retried = risk.authorize(batch, target, lease.fence)

    assert retried == original
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_decisions)) == 1
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_batch_reservations))
            == 1
        )


def test_exact_retry_survives_lease_revision_but_not_a_counterfeit_receipt(
    tmp_path: Path,
) -> None:
    _, target, batch, capacity = mixed_case()
    engine = _engine(tmp_path / "phase2-renewal.sqlite")
    coordinator_clock = MutableClock(EVALUATED_AT)
    coordinator = _coordinator(
        engine,
        clock=coordinator_clock,
        account_id=capacity.account_id,
    )
    lease = coordinator.acquire("worker-a")
    evaluation_clock = MutableClock(EVALUATED_AT)
    risk = _repository(engine, capacity, coordinator, evaluation_clock)
    original = risk.authorize(batch, target, lease.fence)
    coordinator_clock.instant += timedelta(seconds=1)
    evaluation_clock.instant += timedelta(seconds=1)
    renewed = coordinator.renew(lease.fence)

    assert renewed.semantic_sha256 != lease.semantic_sha256
    assert risk.authorize(batch, target, renewed.fence) == original

    class CounterfeitValidator:
        def revalidate_in_transaction(
            self,
            connection: sa.Connection,
            fence: AccountFence,
            *,
            checked_at: object,
        ) -> AccountFenceReceipt:
            del connection, fence
            assert isinstance(checked_at, type(EVALUATED_AT))
            return _account_fence_receipt(
                fence=AccountFence(
                    account_id=capacity.account_id,
                    owner_id="counterfeit-owner",
                    lease_id="counterfeit-lease",
                    fencing_generation=renewed.fencing_generation,
                ),
                validated_at=evaluation_clock.instant,
                valid_until=renewed.expires_at,
                policy_sha256=renewed.policy_sha256,
                lease_sha256=renewed.semantic_sha256,
            )

    counterfeit = SqlBatchRiskRepository(
        engine=engine,
        authority=risk._authority,
        coordinator=CounterfeitValidator(),
    )
    with pytest.raises(BatchRiskFactConflict, match="does not bind"):
        counterfeit.authorize(batch, target, renewed.fence)


def test_parallel_batches_cannot_overreserve_durable_cash(tmp_path: Path) -> None:
    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-QQQ", "US-ETF-SPY"),
    )
    cases: tuple[tuple[TargetPortfolio, OrderIntentBatch], ...] = (
        make_batch(portfolio, desired={"US-ETF-QQQ": Decimal("5")}, target_id="sql-qqq"),
        make_batch(portfolio, desired={"US-ETF-SPY": Decimal("5")}, target_id="sql-spy"),
    )
    capacity = snapshot(portfolio, available_cash=Decimal("700"))
    engine = _engine(tmp_path / "phase2-concurrency.sqlite")
    coordinator_clock = MutableClock(EVALUATED_AT)
    coordinator = _coordinator(
        engine,
        clock=coordinator_clock,
        account_id=capacity.account_id,
    )
    fence = coordinator.acquire("worker-a").fence
    repositories = tuple(
        _repository(
            engine,
            capacity,
            coordinator,
            MutableClock(EVALUATED_AT),
        )
        for _ in cases
    )
    start = threading.Barrier(3)

    def authorize(index: int) -> BatchRiskDecisionStatus:
        start.wait(timeout=10)
        target, batch = cases[index]
        return repositories[index].authorize(batch, target, fence).status

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(authorize, index) for index in range(2)]
        start.wait(timeout=10)
        statuses = [future.result(timeout=20) for future in futures]

    assert sorted(status.value for status in statuses) == ["approved", "rejected"]
    with engine.connect() as connection:
        reservations = connection.execute(sa.select(phase2_batch_reservations)).mappings().all()
        sequences = tuple(
            connection.scalars(
                sa.select(phase2_batch_decisions.c.account_observation_sequence).order_by(
                    phase2_batch_decisions.c.account_observation_sequence
                )
            )
        )
    assert len(reservations) == 1
    assert Decimal(str(reservations[0]["initial_cash"])) == Decimal("504")
    assert sequences == (1, 2)


def test_durable_risk_charges_authenticated_remaining_capacity_and_binds_universe(
    tmp_path: Path,
) -> None:
    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-IWM", "US-ETF-QQQ", "US-ETF-SPY"),
    )
    first_target, first_batch = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("5"), "US-ETF-SPY": Decimal("5")},
        target_id="sql-initial-capacity",
    )
    second_target, second_batch = make_batch(
        portfolio,
        desired={"US-ETF-QQQ": Decimal("5")},
        target_id="sql-released-capacity",
    )
    capacity = snapshot(portfolio, available_cash=Decimal("1100"))
    engine = _engine(tmp_path / "phase2-remaining-capacity.sqlite")
    coordinator_clock = MutableClock(EVALUATED_AT)
    coordinator = _coordinator(
        engine,
        clock=coordinator_clock,
        account_id=capacity.account_id,
    )
    fence = coordinator.acquire("worker-a").fence
    first_risk = _repository(
        engine,
        capacity,
        coordinator,
        MutableClock(EVALUATED_AT),
    )
    first = first_risk.authorize(first_batch, first_target, fence)
    assert first.reservation is not None
    released_child = next(
        item for item in first.authorizations if item.instrument_id == "US-ETF-IWM"
    )
    retained_child = next(
        item for item in first.authorizations if item.instrument_id == "US-ETF-SPY"
    )
    lifecycle = SqlReservationLifecycleRepository(
        engine=engine,
        coordinator=coordinator,
    )
    released_at = first.expires_at + timedelta(seconds=1)
    lifecycle.expire_unsent(
        reservation_id=first.reservation.reservation_id,
        authorization_id=released_child.decision_id,
        fence=fence,
        finality_reference="expired-first-child",
        observed_at=released_at,
        recorded_at=released_at,
    )
    active = first_risk.active_capacity(capacity.account_id)
    assert len(active.reservations) == 1
    assert active.reservations[0].state is ActiveCapacityReservationState.PARTIALLY_RELEASED
    assert active.reservations[0].remaining_cash == retained_child.reserved_cash
    assert active.reservations[0].remaining_buy_exposure == retained_child.reserved_buy_exposure
    assert tuple(item.authorization_id for item in active.authorizations) == (
        retained_child.decision_id,
    )

    second_risk = _repository(
        engine,
        capacity,
        coordinator,
        MutableClock(released_at + timedelta(seconds=1)),
    )
    second = second_risk.authorize(second_batch, second_target, fence)

    assert second.status is BatchRiskDecisionStatus.APPROVED
    assert second.reservation is not None
    assert second.active_capacity_sha256 == active.semantic_sha256
    assert (
        retained_child.reserved_cash + second.reservation.reserved_cash <= capacity.available_cash
    )
    assert (
        first.reservation.reserved_cash + second.reservation.reserved_cash > capacity.available_cash
    )
    with engine.connect() as connection:
        row = (
            connection.execute(
                sa.select(
                    phase2_batch_decisions.c.active_capacity_payload,
                    phase2_batch_decisions.c.active_capacity_sha256,
                ).where(phase2_batch_decisions.c.decision_id == second.decision_id)
            )
            .mappings()
            .one()
        )
    assert row["active_capacity_sha256"] == active.semantic_sha256
    assert isinstance(row["active_capacity_payload"], str)


def test_equal_timestamp_release_precedes_capacity_observation_and_reloads(
    tmp_path: Path,
) -> None:
    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-QQQ", "US-ETF-SPY"),
    )
    first_target, first_batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("5")},
        target_id="same-time-release-parent",
    )
    second_target, second_batch = make_batch(
        portfolio,
        desired={"US-ETF-QQQ": Decimal("5")},
        target_id="same-time-release-observer",
    )
    capacity = snapshot(portfolio, available_cash=Decimal("700"))
    engine = _engine(tmp_path / "phase2-same-time-release-first.sqlite")
    coordinator = _coordinator(
        engine,
        clock=MutableClock(EVALUATED_AT),
        account_id=capacity.account_id,
    )
    fence = coordinator.acquire("worker-a").fence
    first_risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    first = first_risk.authorize(first_batch, first_target, fence)
    assert first.reservation is not None
    release_at = first.expires_at
    lifecycle = SqlReservationLifecycleRepository(engine=engine, coordinator=coordinator)

    released = lifecycle.expire_unsent(
        reservation_id=first.reservation.reservation_id,
        authorization_id=first.authorizations[0].decision_id,
        fence=fence,
        finality_reference="same-time-release-first",
        observed_at=release_at,
        recorded_at=release_at,
    )
    second_risk = _repository(engine, capacity, coordinator, MutableClock(release_at))
    second = second_risk.authorize(second_batch, second_target, fence)

    assert second.status is BatchRiskDecisionStatus.APPROVED
    assert second.reservation is not None
    assert second_risk.get_batch(second.decision_id) == second
    retried = lifecycle.expire_unsent(
        reservation_id=first.reservation.reservation_id,
        authorization_id=first.authorizations[0].decision_id,
        fence=fence,
        finality_reference="same-time-release-first",
        observed_at=release_at,
        recorded_at=release_at,
    )
    assert retried.fact == released.fact
    assert retried.inserted is False
    with engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)


def test_equal_timestamp_decision_then_release_preserves_decision_and_advances_visibility(
    tmp_path: Path,
) -> None:
    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-QQQ", "US-ETF-SPY"),
    )
    first_target, first_batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("5")},
        target_id="same-time-decision-parent",
    )
    second_target, second_batch = make_batch(
        portfolio,
        desired={"US-ETF-QQQ": Decimal("5")},
        target_id="same-time-decision-observer",
    )
    third_target, third_batch = make_batch(
        portfolio,
        desired={"US-ETF-QQQ": Decimal("5")},
        target_id="same-time-post-release-observer",
    )
    capacity = snapshot(portfolio, available_cash=Decimal("700"))
    engine = _engine(tmp_path / "phase2-same-time-decision-first.sqlite")
    coordinator = _coordinator(
        engine,
        clock=MutableClock(EVALUATED_AT),
        account_id=capacity.account_id,
    )
    fence = coordinator.acquire("worker-a").fence
    first = _repository(
        engine,
        capacity,
        coordinator,
        MutableClock(EVALUATED_AT),
    ).authorize(first_batch, first_target, fence)
    assert first.reservation is not None
    release_at = first.expires_at
    second_risk = _repository(engine, capacity, coordinator, MutableClock(release_at))
    second = second_risk.authorize(second_batch, second_target, fence)
    assert second.status is BatchRiskDecisionStatus.REJECTED
    lifecycle = SqlReservationLifecycleRepository(engine=engine, coordinator=coordinator)

    released = lifecycle.expire_unsent(
        reservation_id=first.reservation.reservation_id,
        authorization_id=first.authorizations[0].decision_id,
        fence=fence,
        finality_reference="same-time-decision-first",
        observed_at=release_at,
        recorded_at=release_at,
    )

    assert second_risk.get_batch(second.decision_id) == second
    third = _repository(
        engine,
        capacity,
        coordinator,
        MutableClock(release_at),
    ).authorize(third_batch, third_target, fence)
    assert third.status is BatchRiskDecisionStatus.APPROVED
    assert third.reservation is not None
    assert released.fact.recorded_at == third.evaluated_at
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase2_reservation_release_events)
            )
            == 1
        )
        _verify_phase2_durability_integrity(connection)


def test_legacy_equal_timestamp_partial_release_prefix_remains_readable(
    tmp_path: Path,
) -> None:
    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-IWM", "US-ETF-QQQ", "US-ETF-SPY"),
    )
    first_target, first_batch = make_batch(
        portfolio,
        desired={"US-ETF-IWM": Decimal("5"), "US-ETF-SPY": Decimal("5")},
        target_id="legacy-equal-prefix-parent",
    )
    second_target, second_batch = make_batch(
        portfolio,
        desired={"US-ETF-QQQ": Decimal("1")},
        target_id="legacy-equal-prefix-observer",
    )
    capacity = snapshot(portfolio, available_cash=Decimal("2000"))
    engine = _engine(tmp_path / "phase2-legacy-equal-prefix.sqlite")
    coordinator = _coordinator(
        engine,
        clock=MutableClock(EVALUATED_AT),
        account_id=capacity.account_id,
    )
    fence = coordinator.acquire("worker-a").fence
    first_risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    first = first_risk.authorize(first_batch, first_target, fence)
    assert first.reservation is not None
    assert len(first.authorizations) == 2
    release_at = first.expires_at
    lifecycle = SqlReservationLifecycleRepository(engine=engine, coordinator=coordinator)
    lifecycle.expire_unsent(
        reservation_id=first.reservation.reservation_id,
        authorization_id=first.authorizations[0].decision_id,
        fence=fence,
        finality_reference="legacy-equal-prefix-first",
        observed_at=release_at,
        recorded_at=release_at,
    )
    second_risk = _repository(engine, capacity, coordinator, MutableClock(release_at))
    second = second_risk.authorize(second_batch, second_target, fence)
    with engine.connect() as connection:
        observed_payload = connection.scalar(
            sa.select(phase2_batch_decisions.c.active_capacity_payload).where(
                phase2_batch_decisions.c.decision_id == second.decision_id
            )
        )
    observed = _decode_active_capacity(observed_payload)
    assert len(observed.reservations) == 1
    assert len(observed.reservations[0].authorizations) == 1
    lifecycle.expire_unsent(
        reservation_id=first.reservation.reservation_id,
        authorization_id=first.authorizations[1].decision_id,
        fence=fence,
        finality_reference="legacy-equal-prefix-second",
        observed_at=release_at,
        recorded_at=release_at,
    )

    _rewrite_capacity_facts_as_legacy(engine)

    assert second_risk.get_batch(second.decision_id) == second
    with engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)


def test_legacy_completeness_requires_strictly_earlier_terminal_release(
    tmp_path: Path,
) -> None:
    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-QQQ", "US-ETF-SPY"),
    )
    first_target, first_batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("5")},
        target_id="legacy-strict-release-parent",
    )
    second_target, second_batch = make_batch(
        portfolio,
        desired={"US-ETF-QQQ": Decimal("5")},
        target_id="legacy-strict-release-observer",
    )
    capacity = snapshot(portfolio, available_cash=Decimal("700"))
    engine = _engine(tmp_path / "phase2-legacy-strict-release.sqlite")
    coordinator = _coordinator(
        engine,
        clock=MutableClock(EVALUATED_AT),
        account_id=capacity.account_id,
    )
    fence = coordinator.acquire("worker-a").fence
    first_risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    first = first_risk.authorize(first_batch, first_target, fence)
    assert first.reservation is not None
    release_at = first.expires_at
    lifecycle = SqlReservationLifecycleRepository(engine=engine, coordinator=coordinator)
    lifecycle.expire_unsent(
        reservation_id=first.reservation.reservation_id,
        authorization_id=first.authorizations[0].decision_id,
        fence=fence,
        finality_reference="legacy-equal-terminal-release",
        observed_at=release_at,
        recorded_at=release_at,
    )
    second_risk = _repository(engine, capacity, coordinator, MutableClock(release_at))
    second = second_risk.authorize(second_batch, second_target, fence)
    with engine.connect() as connection:
        observed_payload = connection.scalar(
            sa.select(phase2_batch_decisions.c.active_capacity_payload).where(
                phase2_batch_decisions.c.decision_id == second.decision_id
            )
        )
    assert _decode_active_capacity(observed_payload).reservations == ()

    _rewrite_capacity_facts_as_legacy(engine)

    with pytest.raises(BatchRiskFactConflict, match="terminal release evidence"):
        second_risk.get_batch(second.decision_id)


def test_equal_timestamp_history_rejects_a_stale_pre_release_capacity_prefix(
    tmp_path: Path,
) -> None:
    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-QQQ", "US-ETF-SPY"),
    )
    first_target, first_batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("1")},
        target_id="same-time-stale-parent",
    )
    second_target, second_batch = make_batch(
        portfolio,
        desired={"US-ETF-QQQ": Decimal("1")},
        target_id="same-time-stale-observer",
    )
    capacity = snapshot(portfolio, available_cash=Decimal("1000"))
    engine = _engine(tmp_path / "phase2-same-time-stale-prefix.sqlite")
    coordinator = _coordinator(
        engine,
        clock=MutableClock(EVALUATED_AT),
        account_id=capacity.account_id,
    )
    fence = coordinator.acquire("worker-a").fence
    risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    first = risk.authorize(first_batch, first_target, fence)
    assert first.reservation is not None
    stale_capacity = risk.active_capacity(capacity.account_id)
    release_at = first.expires_at
    lifecycle = SqlReservationLifecycleRepository(engine=engine, coordinator=coordinator)
    lifecycle.expire_unsent(
        reservation_id=first.reservation.reservation_id,
        authorization_id=first.authorizations[0].decision_id,
        fence=fence,
        finality_reference="same-time-stale-release",
        observed_at=release_at,
        recorded_at=release_at,
    )
    second_risk = _repository(engine, capacity, coordinator, MutableClock(release_at))
    second = second_risk.authorize(second_batch, second_target, fence)
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase2_batch_decisions)
            .where(phase2_batch_decisions.c.decision_id == second.decision_id)
            .values(
                active_capacity_payload=_active_capacity_payload(stale_capacity),
                active_capacity_sha256=stale_capacity.semantic_sha256,
            )
        )

    with pytest.raises(BatchRiskFactConflict, match="exact historical"):
        second_risk.get_batch(second.decision_id)


def test_active_capacity_rejects_manual_frozen_head_without_immutable_provenance(
    tmp_path: Path,
) -> None:
    _, target, batch, capacity = mixed_case()
    engine = _engine(tmp_path / "phase2-forged-freeze.sqlite")
    clock = MutableClock(EVALUATED_AT)
    coordinator = _coordinator(engine, clock=clock, account_id=capacity.account_id)
    fence = coordinator.acquire("worker-a").fence
    risk = _repository(engine, capacity, coordinator, clock)
    decision = risk.authorize(batch, target, fence)
    assert decision.reservation is not None
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase2_batch_reservations)
            .where(
                phase2_batch_reservations.c.reservation_id == decision.reservation.reservation_id
            )
            .values(
                state=ActiveCapacityReservationState.FROZEN.value,
                state_version=phase2_batch_reservations.c.state_version + 1,
            )
        )

    with pytest.raises(BatchRiskFactConflict, match="immutable freeze provenance"):
        risk.active_capacity(capacity.account_id)


def test_read_boundary_rejects_noncanonical_active_capacity_payload(
    tmp_path: Path,
) -> None:
    _, target, batch, capacity = mixed_case()
    engine = _engine(tmp_path / "phase2-corrupt-capacity.sqlite")
    clock = MutableClock(EVALUATED_AT)
    coordinator = _coordinator(engine, clock=clock, account_id=capacity.account_id)
    lease = coordinator.acquire("worker-a")
    risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    decision = risk.authorize(batch, target, lease.fence)
    with engine.begin() as connection:
        payload = connection.scalar(
            sa.select(phase2_batch_decisions.c.active_capacity_payload).where(
                phase2_batch_decisions.c.decision_id == decision.decision_id
            )
        )
        assert isinstance(payload, str)
        connection.execute(
            sa.update(phase2_batch_decisions)
            .where(phase2_batch_decisions.c.decision_id == decision.decision_id)
            .values(active_capacity_payload=f" {payload}")
        )

    with pytest.raises(BatchRiskFactConflict, match="not canonical JSON"):
        risk.get_batch(decision.decision_id)


def test_read_boundary_rejects_self_consistent_capacity_with_forged_sql_reference(
    tmp_path: Path,
) -> None:
    portfolio = make_portfolio(current={}, instruments=("US-ETF-SPY",))
    first_target, first_batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("1")},
        target_id="capacity-reference-parent",
    )
    second_target, second_batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("2")},
        target_id="capacity-reference-child",
    )
    capacity = snapshot(portfolio, available_cash=Decimal("1000"))
    engine = _engine(tmp_path / "phase2-forged-capacity-reference.sqlite")
    coordinator = _coordinator(
        engine,
        clock=MutableClock(EVALUATED_AT),
        account_id=capacity.account_id,
    )
    fence = coordinator.acquire("worker-a").fence
    first_risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    first = first_risk.authorize(first_batch, first_target, fence)
    assert first.reservation is not None
    second_risk = _repository(
        engine,
        capacity,
        coordinator,
        MutableClock(EVALUATED_AT + timedelta(seconds=1)),
    )
    second = second_risk.authorize(second_batch, second_target, fence)

    with engine.begin() as connection:
        raw = connection.scalar(
            sa.select(phase2_batch_decisions.c.active_capacity_payload).where(
                phase2_batch_decisions.c.decision_id == second.decision_id
            )
        )
        universe = _decode_active_capacity(raw)
        reservation = universe.reservations[0]
        forged_child = replace(
            reservation.authorizations[0],
            authorization_sha256="0" * 64,
        )
        forged_reservation = replace(
            reservation,
            authorizations=(forged_child, *reservation.authorizations[1:]),
        )
        forged_universe = replace(universe, reservations=(forged_reservation,))
        connection.execute(
            sa.update(phase2_batch_decisions)
            .where(phase2_batch_decisions.c.decision_id == second.decision_id)
            .values(
                active_capacity_payload=_active_capacity_payload(forged_universe),
                active_capacity_sha256=forged_universe.semantic_sha256,
            )
        )

    with pytest.raises(BatchRiskFactConflict, match="historical lifecycle prefix"):
        second_risk.get_batch(second.decision_id)


def test_read_boundary_rejects_self_consistent_omission_of_prior_capacity(
    tmp_path: Path,
) -> None:
    portfolio = make_portfolio(current={}, instruments=("US-ETF-SPY",))
    first_target, first_batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("1")},
        target_id="capacity-omission-parent",
    )
    second_target, second_batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("2")},
        target_id="capacity-omission-child",
    )
    capacity = snapshot(portfolio, available_cash=Decimal("1000"))
    engine = _engine(tmp_path / "phase2-capacity-omission.sqlite")
    coordinator = _coordinator(
        engine,
        clock=MutableClock(EVALUATED_AT),
        account_id=capacity.account_id,
    )
    fence = coordinator.acquire("worker-a").fence
    first_risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    first = first_risk.authorize(first_batch, first_target, fence)
    assert first.reservation is not None
    second_risk = _repository(
        engine,
        capacity,
        coordinator,
        MutableClock(EVALUATED_AT),
    )
    second = second_risk.authorize(second_batch, second_target, fence)

    with engine.begin() as connection:
        raw = connection.scalar(
            sa.select(phase2_batch_decisions.c.active_capacity_payload).where(
                phase2_batch_decisions.c.decision_id == second.decision_id
            )
        )
        universe = _decode_active_capacity(raw)
        assert universe.reservations
        omitted = replace(universe, reservations=())
        connection.execute(
            sa.update(phase2_batch_decisions)
            .where(phase2_batch_decisions.c.decision_id == second.decision_id)
            .values(
                active_capacity_payload=_active_capacity_payload(omitted),
                active_capacity_sha256=omitted.semantic_sha256,
            )
        )

    with pytest.raises(BatchRiskFactConflict, match="omits a prior reservation"):
        second_risk.get_batch(second.decision_id)


def test_read_boundary_rejects_noncanonical_rules_payload(tmp_path: Path) -> None:
    _, target, batch, capacity = mixed_case()
    engine = _engine(tmp_path / "phase2-corrupt.sqlite")
    clock = MutableClock(EVALUATED_AT)
    coordinator = _coordinator(engine, clock=clock, account_id=capacity.account_id)
    lease = coordinator.acquire("worker-a")
    risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    decision = risk.authorize(batch, target, lease.fence)
    with engine.begin() as connection:
        payload = connection.scalar(
            sa.select(phase2_batch_decisions.c.rules_payload).where(
                phase2_batch_decisions.c.decision_id == decision.decision_id
            )
        )
        assert isinstance(payload, str)
        connection.execute(
            sa.update(phase2_batch_decisions)
            .where(phase2_batch_decisions.c.decision_id == decision.decision_id)
            .values(rules_payload=f" {payload}")
        )

    with pytest.raises(BatchRiskFactConflict, match="not canonical JSON"):
        risk.get_batch(decision.decision_id)


def test_read_boundary_authenticates_fence_members_and_reservation_time(
    tmp_path: Path,
) -> None:
    _, target, batch, capacity = mixed_case()
    engine = _engine(tmp_path / "phase2-envelope.sqlite")
    clock = MutableClock(EVALUATED_AT)
    coordinator = _coordinator(engine, clock=clock, account_id=capacity.account_id)
    lease = coordinator.acquire("worker-a")
    risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    decision = risk.authorize(batch, target, lease.fence)
    assert decision.reservation is not None
    with engine.connect() as connection:
        assert connection.scalar(
            sa.select(sa.func.count()).select_from(phase2_batch_members)
        ) == len(batch.intents)

    with engine.begin() as connection:
        connection.execute(
            sa.update(phase2_batch_authorizations)
            .where(phase2_batch_authorizations.c.parent_decision_id == decision.decision_id)
            .values(fence_sha256="f" * 64)
        )
    with pytest.raises(BatchRiskFactConflict, match="fence digest conflicts"):
        risk.get_batch(decision.decision_id)

    with engine.begin() as connection:
        connection.execute(
            sa.update(phase2_batch_authorizations)
            .where(phase2_batch_authorizations.c.parent_decision_id == decision.decision_id)
            .values(fence_sha256=lease.fence.semantic_sha256)
        )
        connection.execute(
            sa.update(phase2_batch_reservations)
            .where(
                phase2_batch_reservations.c.reservation_id == decision.reservation.reservation_id
            )
            .values(created_at=decision.evaluated_at + timedelta(microseconds=1))
        )
    with pytest.raises(BatchRiskFactConflict, match="timing disagrees"):
        risk.get_batch(decision.decision_id)


def test_active_capacity_rejects_release_head_without_release_facts(tmp_path: Path) -> None:
    _, target, batch, capacity = mixed_case()
    engine = _engine(tmp_path / "phase2-false-release.sqlite")
    clock = MutableClock(EVALUATED_AT)
    coordinator = _coordinator(engine, clock=clock, account_id=capacity.account_id)
    lease = coordinator.acquire("worker-a")
    risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    decision = risk.authorize(batch, target, lease.fence)
    assert decision.reservation is not None
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase2_batch_reservations)
            .where(
                phase2_batch_reservations.c.reservation_id == decision.reservation.reservation_id
            )
            .values(
                state="released",
                state_version=phase2_batch_reservations.c.state_version + 1,
                remaining_authorization_count=0,
                remaining_cash=Decimal(0),
                remaining_buy_exposure=Decimal(0),
                released_at=EVALUATED_AT + timedelta(seconds=1),
            )
        )

    with pytest.raises(BatchRiskFactConflict, match="mutable head"):
        risk.active_reservations(capacity.account_id)


def test_repository_requires_sql_fence_validator(tmp_path: Path) -> None:
    _, _, _, capacity = mixed_case()
    engine = _engine(tmp_path / "phase2-validator.sqlite")
    authority = BatchRiskAuthority(
        limits=limits(),
        snapshots=SnapshotTransactions(capacity),
        evaluation_clock=MutableClock(EVALUATED_AT),
        consumption_clock=MutableClock(CONSUMED_AT),
    )
    in_memory = InMemoryAccountCoordinatorAuthority(
        policy=AccountLeasePolicy(
            policy_id="process-only",
            policy_version="1",
            lease_ttl=timedelta(seconds=30),
            maximum_in_flight_duration=timedelta(seconds=5),
            takeover_safety_interval=timedelta(seconds=10),
        ),
        clock=MutableClock(EVALUATED_AT),
    )

    with pytest.raises(BatchRiskFactConflict, match="SQL fence validator"):
        SqlBatchRiskRepository(
            engine=engine,
            authority=authority,
            coordinator=in_memory,  # type: ignore[arg-type]
        )
