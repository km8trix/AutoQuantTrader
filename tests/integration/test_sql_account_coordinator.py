"""Durable account-coordinator lease, fence, and locking proofs."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFenceReceipt,
    AccountLease,
    AccountLeaseConflict,
    AccountLeaseOwnershipLost,
    AccountLeasePolicy,
    AccountLeaseRelease,
)
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
    account_lease_from_row,
    account_lease_release_from_row,
    immutable_account_lease_release_values,
    immutable_account_lease_values,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    _verify_phase2_durability_integrity,
    create_database_engine,
)
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
)

BASE = datetime(2026, 7, 20, 13, 30, tzinfo=UTC)


@dataclass
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant

    def advance(self, delta: timedelta) -> None:
        self.instant += delta


class SequenceClock:
    def __init__(self, *instants: datetime) -> None:
        self.instants = list(instants)

    def now(self) -> datetime:
        if not self.instants:
            raise AssertionError("test clock was sampled more times than expected")
        return self.instants.pop(0)


def policy(*, version: str = "1.0.0") -> AccountLeasePolicy:
    return AccountLeasePolicy(
        policy_id="phase2-sql-coordinator",
        policy_version=version,
        lease_ttl=timedelta(seconds=30),
        maximum_in_flight_duration=timedelta(seconds=5),
        takeover_safety_interval=timedelta(seconds=10),
    )


@pytest.fixture
def sqlite_engine(tmp_path: Path) -> Iterator[Engine]:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'coordinator.sqlite'}")
    metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


def coordinator(
    engine: Engine,
    account_id: str,
    *,
    clock: MutableClock | None = None,
    lease_policy: AccountLeasePolicy | None = None,
) -> tuple[SqlAccountCoordinator, MutableClock, SqlAccountCoordinatorAuthority]:
    trusted_clock = MutableClock(BASE) if clock is None else clock
    authority = SqlAccountCoordinatorAuthority(
        engine=engine,
        policy=policy() if lease_policy is None else lease_policy,
        clock=trusted_clock,
    )
    return (
        SqlAccountCoordinator(account_id=account_id, authority=authority),
        trusted_clock,
        authority,
    )


def coordinator_evidence(
    engine: Engine,
    account_id: str,
) -> tuple[tuple[object, ...], tuple[object, ...], tuple[object, ...]]:
    with engine.connect() as connection:
        heads = tuple(
            connection.execute(
                sa.select(phase2_account_lease_heads)
                .where(phase2_account_lease_heads.c.account_id == account_id)
                .order_by(phase2_account_lease_heads.c.account_id)
            )
        )
        leases = tuple(
            connection.execute(
                sa.select(phase2_account_leases)
                .where(phase2_account_leases.c.account_id == account_id)
                .order_by(
                    phase2_account_leases.c.fencing_generation,
                    phase2_account_leases.c.revision_number,
                )
            )
        )
        releases = tuple(
            connection.execute(
                sa.select(phase2_account_lease_releases)
                .where(phase2_account_lease_releases.c.account_id == account_id)
                .order_by(phase2_account_lease_releases.c.fencing_generation)
            )
        )
    return heads, leases, releases


def test_lease_renewal_and_release_rows_use_strict_canonical_readback(
    sqlite_engine: Engine,
) -> None:
    account_coordinator, clock, _ = coordinator(sqlite_engine, "canonical-account")

    first = account_coordinator.acquire("worker-a")
    assert immutable_account_lease_values(first)["lease_sha256"] == first.semantic_sha256
    with sqlite_engine.connect() as connection:
        first_row = (
            connection.execute(
                sa.select(phase2_account_leases).where(
                    phase2_account_leases.c.lease_sha256 == first.semantic_sha256
                )
            )
            .mappings()
            .one()
        )
    assert account_lease_from_row(first_row) == first
    malformed_lease = dict(first_row)
    malformed_lease["canonical_payload"] = "{}"
    with pytest.raises(AccountCoordinatorError, match="canonical payload conflicts"):
        account_lease_from_row(malformed_lease)

    clock.advance(timedelta(seconds=10))
    renewed = account_coordinator.renew(first.fence)
    receipt = account_coordinator.revalidate(first.fence)

    assert renewed.fence == first.fence
    assert renewed.semantic_sha256 != first.semantic_sha256
    assert first.revision_number == 1
    assert first.previous_lease_sha256 is None
    assert renewed.revision_number == 2
    assert renewed.previous_lease_sha256 == first.semantic_sha256
    assert renewed.acquired_at == first.acquired_at
    assert renewed.heartbeat_at == BASE + timedelta(seconds=10)
    assert renewed.expires_at == BASE + timedelta(seconds=40)
    assert receipt.lease_sha256 == renewed.semantic_sha256
    assert receipt.valid_until == renewed.expires_at
    with sqlite_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase2_account_leases)
                .where(phase2_account_leases.c.account_id == "canonical-account")
            )
            == 2
        )
        head = (
            connection.execute(
                sa.select(phase2_account_lease_heads).where(
                    phase2_account_lease_heads.c.account_id == "canonical-account"
                )
            )
            .mappings()
            .one()
        )
    assert head["current_lease_sha256"] == renewed.semantic_sha256
    assert head["current_fencing_generation"] == first.fencing_generation

    clock.advance(timedelta(seconds=1))
    release = account_coordinator.release(first.fence)
    assert immutable_account_lease_release_values(release)["release_id"] == release.release_id
    with sqlite_engine.connect() as connection:
        release_row = (
            connection.execute(
                sa.select(phase2_account_lease_releases).where(
                    phase2_account_lease_releases.c.release_id == release.release_id
                )
            )
            .mappings()
            .one()
        )
    assert account_lease_release_from_row(release_row) == release
    malformed_release = dict(release_row)
    malformed_release["release_sha256"] = "0" * 64
    with pytest.raises(AccountCoordinatorError, match="release digest conflicts"):
        account_lease_release_from_row(malformed_release)


def test_clean_handoff_is_idempotent_and_generation_survives_new_authority(
    sqlite_engine: Engine,
) -> None:
    first_coordinator, clock, _ = coordinator(sqlite_engine, "handoff-account")
    first = first_coordinator.acquire("worker-a")

    assert first.fencing_generation == 1
    assert first_coordinator.acquire("worker-a") == first
    with pytest.raises(AccountLeaseConflict, match="active coordinator owner"):
        first_coordinator.acquire("worker-b")

    clock.advance(timedelta(seconds=1))
    release = first_coordinator.release(first.fence)
    assert first_coordinator.release(first.fence) == release
    assert first_coordinator.current() is None

    restarted_coordinator, _, _ = coordinator(
        sqlite_engine,
        "handoff-account",
        clock=clock,
    )
    second = restarted_coordinator.acquire("worker-b")

    assert second.fencing_generation == 2
    assert second.owner_id == "worker-b"
    assert first_coordinator.release(first.fence) == release
    with pytest.raises(AccountLeaseOwnershipLost, match="no longer current"):
        restarted_coordinator.revalidate(first.fence)
    with sqlite_engine.connect() as connection:
        head = (
            connection.execute(
                sa.select(phase2_account_lease_heads).where(
                    phase2_account_lease_heads.c.account_id == "handoff-account"
                )
            )
            .mappings()
            .one()
        )
        release_count = connection.scalar(
            sa.select(sa.func.count())
            .select_from(phase2_account_lease_releases)
            .where(phase2_account_lease_releases.c.account_id == "handoff-account")
        )
    assert head["last_fencing_generation"] == 2
    assert head["current_lease_sha256"] == second.semantic_sha256
    assert release_count == 1

    incompatible, _, _ = coordinator(
        sqlite_engine,
        "handoff-account",
        clock=clock,
        lease_policy=policy(version="2.0.0"),
    )
    with pytest.raises(AccountLeaseConflict, match="policy conflicts"):
        incompatible.current()


def test_conditional_acquisition_advances_one_exact_inactive_generation(
    sqlite_engine: Engine,
) -> None:
    account_coordinator, clock, _ = coordinator(
        sqlite_engine,
        "conditional-acquire-account",
    )
    first = account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=1))
    account_coordinator.release(first.fence)
    clock.advance(timedelta(seconds=1))

    second = account_coordinator.acquire_if_inactive_generation(
        "worker-b",
        expected_last_fencing_generation=1,
    )

    assert second.owner_id == "worker-b"
    assert second.fencing_generation == 2
    assert second.revision_number == 1
    assert account_coordinator.current() == second


def test_stale_conditional_acquisition_has_zero_durable_mutation(
    sqlite_engine: Engine,
) -> None:
    account_coordinator, clock, _ = coordinator(
        sqlite_engine,
        "stale-conditional-account",
    )
    first = account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=1))
    account_coordinator.release(first.fence)
    clock.advance(timedelta(seconds=1))
    second = account_coordinator.acquire("worker-b")
    clock.advance(timedelta(seconds=1))
    account_coordinator.release(second.fence)
    before = coordinator_evidence(sqlite_engine, account_coordinator.account_id)
    clock.advance(timedelta(seconds=1))

    with pytest.raises(AccountLeaseConflict, match="expected checkpoint"):
        account_coordinator.acquire_if_inactive_generation(
            "worker-c",
            expected_last_fencing_generation=1,
        )

    assert coordinator_evidence(sqlite_engine, account_coordinator.account_id) == before
    assert account_coordinator.current() is None
    with sqlite_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.max(phase2_account_leases.c.fencing_generation)).where(
                    phase2_account_leases.c.account_id == account_coordinator.account_id
                )
            )
            == 2
        )


def test_conditional_acquisition_rejects_missing_head_without_bootstrap(
    sqlite_engine: Engine,
) -> None:
    account_coordinator, _, _ = coordinator(
        sqlite_engine,
        "missing-conditional-account",
    )

    with pytest.raises(AccountLeaseConflict, match="expected checkpoint"):
        account_coordinator.acquire_if_inactive_generation(
            "worker-a",
            expected_last_fencing_generation=1,
        )

    assert coordinator_evidence(sqlite_engine, account_coordinator.account_id) == ((), (), ())


@pytest.mark.parametrize("expected_generation", [True, -1, 1.0, "1"])
def test_conditional_acquisition_requires_exact_non_negative_generation(
    sqlite_engine: Engine,
    expected_generation: object,
) -> None:
    account_coordinator, _, _ = coordinator(
        sqlite_engine,
        "invalid-conditional-account",
    )

    with pytest.raises(AccountCoordinatorError, match="non-negative exact integer"):
        account_coordinator.acquire_if_inactive_generation(
            "worker-a",
            expected_last_fencing_generation=expected_generation,  # type: ignore[arg-type]
        )

    assert coordinator_evidence(sqlite_engine, account_coordinator.account_id) == ((), (), ())


def test_concurrent_conditional_acquisition_has_one_generation_two_winner(
    sqlite_engine: Engine,
) -> None:
    primary, clock, _ = coordinator(sqlite_engine, "parallel-conditional-account")
    first = primary.acquire("worker-a")
    clock.advance(timedelta(seconds=1))
    primary.release(first.fence)
    clock.advance(timedelta(seconds=1))
    start = threading.Barrier(3)

    def acquire(owner_id: str) -> AccountLease | AccountLeaseConflict:
        contender, _, _ = coordinator(
            sqlite_engine,
            "parallel-conditional-account",
            clock=MutableClock(clock.instant),
        )
        start.wait(timeout=10)
        try:
            return contender.acquire_if_inactive_generation(
                owner_id,
                expected_last_fencing_generation=1,
            )
        except AccountLeaseConflict as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(acquire, "worker-b") for _ in range(2)]
        start.wait(timeout=10)
        outcomes = [future.result(timeout=10) for future in futures]

    leases = [outcome for outcome in outcomes if type(outcome) is AccountLease]
    conflicts = [outcome for outcome in outcomes if type(outcome) is AccountLeaseConflict]
    assert len(leases) == 1
    assert len(conflicts) == 1
    assert leases[0].fencing_generation == 2
    heads, durable_leases, releases = coordinator_evidence(
        sqlite_engine,
        "parallel-conditional-account",
    )
    assert len(heads) == 1
    assert len(durable_leases) == 2
    assert len(releases) == 1


@pytest.mark.parametrize("corruption", ["prior_release", "prior_generation"])
def test_full_history_reconstruction_rejects_deleted_prior_generation_evidence(
    sqlite_engine: Engine,
    corruption: str,
) -> None:
    account_coordinator, clock, _ = coordinator(sqlite_engine, "history-account")
    first = account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=1))
    renewed_first = account_coordinator.renew(first.fence)
    assert renewed_first.semantic_sha256 != first.semantic_sha256
    clock.advance(timedelta(seconds=1))
    account_coordinator.release(first.fence)
    clock.advance(timedelta(seconds=1))
    second = account_coordinator.acquire("worker-b")

    assert account_coordinator.current() == second
    with sqlite_engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)

    with sqlite_engine.begin() as connection:
        connection.execute(
            sa.delete(phase2_account_lease_releases).where(
                phase2_account_lease_releases.c.account_id == "history-account",
                phase2_account_lease_releases.c.fencing_generation == 1,
            )
        )
        if corruption == "prior_generation":
            connection.execute(
                sa.delete(phase2_account_leases).where(
                    phase2_account_leases.c.account_id == "history-account",
                    phase2_account_leases.c.fencing_generation == 1,
                )
            )

    expected = (
        "canonical terminal release"
        if corruption == "prior_release"
        else "generations are not contiguous"
    )
    with pytest.raises(AccountCoordinatorError, match=expected):
        account_coordinator.current()
    with (
        sqlite_engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_full_history_reconstruction_rejects_deleted_middle_renewal(
    sqlite_engine: Engine,
) -> None:
    account_coordinator, clock, _ = coordinator(sqlite_engine, "renewal-gap-account")
    first = account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=1))
    second_revision = account_coordinator.renew(first.fence)
    clock.advance(timedelta(seconds=1))
    third_revision = account_coordinator.renew(first.fence)
    clock.advance(timedelta(seconds=1))
    account_coordinator.release(first.fence)
    clock.advance(timedelta(seconds=1))
    second_generation = account_coordinator.acquire("worker-b")

    assert second_revision.revision_number == 2
    assert third_revision.revision_number == 3
    assert third_revision.previous_lease_sha256 == second_revision.semantic_sha256
    assert account_coordinator.current() == second_generation
    with sqlite_engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)

    # Simulate storage-level corruption below the relational guard so the
    # application/readiness reconstruction must independently detect the gap.
    with sqlite_engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys = OFF")
        connection.execute(
            sa.delete(phase2_account_leases).where(
                phase2_account_leases.c.lease_sha256 == second_revision.semantic_sha256
            )
        )
        connection.commit()
        connection.exec_driver_sql("PRAGMA foreign_keys = ON")

    with pytest.raises(AccountCoordinatorError, match="revision numbers are not contiguous"):
        account_coordinator.current()
    with (
        sqlite_engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_abandoned_expiry_blocks_every_transition_and_persists_clock_watermark(
    sqlite_engine: Engine,
) -> None:
    account_coordinator, clock, _ = coordinator(sqlite_engine, "expired-account")
    lease = account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=30))
    called = False

    def effect(_receipt: AccountFenceReceipt) -> None:
        nonlocal called
        called = True

    with pytest.raises(AccountLeaseOwnershipLost, match="expired"):
        account_coordinator.run_fenced(lease.fence, effect)
    with pytest.raises(AccountLeaseOwnershipLost, match="expired"):
        account_coordinator.renew(lease.fence)
    with pytest.raises(AccountLeaseOwnershipLost, match="expired"):
        account_coordinator.release(lease.fence)
    with pytest.raises(AccountLeaseOwnershipLost, match="durable reconciliation takeover"):
        account_coordinator.acquire("worker-b")
    assert called is False
    assert account_coordinator.current() == lease

    # The failed expiry observation was committed while the lease remained
    # untouched, so moving back into its former active interval fails closed.
    clock.instant = BASE + timedelta(seconds=1)
    with pytest.raises(AccountCoordinatorError, match="cannot regress"):
        account_coordinator.acquire("worker-a")


def test_transactional_revalidation_locks_and_binds_the_exact_revision(
    sqlite_engine: Engine,
) -> None:
    account_coordinator, clock, _ = coordinator(sqlite_engine, "transaction-account")
    lease = account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=2))

    with (
        sqlite_engine.connect() as connection,
        pytest.raises(AccountCoordinatorError, match="active SQLAlchemy transaction"),
    ):
        account_coordinator.revalidate_in_transaction(
            connection,
            lease.fence,
            checked_at=clock.instant,
        )

    with sqlite_engine.begin() as connection:
        receipt = account_coordinator.revalidate_in_transaction(
            connection,
            lease.fence,
            checked_at=clock.instant,
        )
        locked_head = (
            connection.execute(
                sa.select(phase2_account_lease_heads).where(
                    phase2_account_lease_heads.c.account_id == "transaction-account"
                )
            )
            .mappings()
            .one()
        )

    assert receipt.fence == lease.fence
    assert receipt.lease_sha256 == lease.semantic_sha256
    assert receipt.validated_at == clock.instant
    persisted_updated_at = locked_head["updated_at"]
    assert isinstance(persisted_updated_at, datetime)
    assert persisted_updated_at.replace(tzinfo=UTC) == clock.instant

    with (
        sqlite_engine.begin() as connection,
        pytest.raises(AccountCoordinatorError, match="cannot regress"),
    ):
        account_coordinator.revalidate_in_transaction(
            connection,
            lease.fence,
            checked_at=BASE + timedelta(seconds=1),
        )


def test_commit_revalidation_rejects_regression_between_authority_samples(
    sqlite_engine: Engine,
) -> None:
    clock = SequenceClock(
        BASE,
        BASE + timedelta(seconds=10),
        BASE + timedelta(seconds=5),
    )
    authority = SqlAccountCoordinatorAuthority(
        engine=sqlite_engine,
        policy=policy(),
        clock=clock,
    )
    account_coordinator = SqlAccountCoordinator(
        account_id="commit-regression-account",
        authority=authority,
    )
    lease = account_coordinator.acquire("worker-a")

    with (
        pytest.raises(
            AccountCoordinatorError,
            match="cannot regress during commit validation",
        ),
        sqlite_engine.begin() as connection,
    ):
        account_coordinator.revalidate_for_commit_in_transaction(
            connection,
            lease.fence,
        )

    with sqlite_engine.connect() as connection:
        head_updated_at = connection.scalar(
            sa.select(phase2_account_lease_heads.c.updated_at).where(
                phase2_account_lease_heads.c.account_id == "commit-regression-account"
            )
        )
    assert isinstance(head_updated_at, datetime)
    assert head_updated_at.replace(tzinfo=UTC) == BASE


def test_transactional_revalidation_cannot_backdate_past_trusted_expiry(
    sqlite_engine: Engine,
) -> None:
    account_coordinator, clock, _ = coordinator(sqlite_engine, "backdated-account")
    lease = account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=31))

    with (
        sqlite_engine.begin() as connection,
        pytest.raises(AccountLeaseOwnershipLost, match="expired"),
    ):
        account_coordinator.revalidate_in_transaction(
            connection,
            lease.fence,
            checked_at=BASE + timedelta(seconds=1),
        )

    with sqlite_engine.connect() as connection:
        head_updated_at = connection.scalar(
            sa.select(phase2_account_lease_heads.c.updated_at).where(
                phase2_account_lease_heads.c.account_id == "backdated-account"
            )
        )
    assert isinstance(head_updated_at, datetime)
    assert head_updated_at.replace(tzinfo=UTC) == BASE


def test_concurrent_first_acquisition_has_one_durable_winner(sqlite_engine: Engine) -> None:
    start = threading.Barrier(3)

    def acquire(owner_id: str) -> AccountLease | AccountLeaseConflict:
        contender, _, _ = coordinator(sqlite_engine, "parallel-account")
        start.wait(timeout=10)
        try:
            return contender.acquire(owner_id)
        except AccountLeaseConflict as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(acquire, owner_id) for owner_id in ("worker-a", "worker-b")]
        start.wait(timeout=10)
        outcomes = [future.result(timeout=10) for future in futures]

    leases = [outcome for outcome in outcomes if type(outcome) is AccountLease]
    conflicts = [outcome for outcome in outcomes if type(outcome) is AccountLeaseConflict]
    assert len(leases) == 1
    assert len(conflicts) == 1
    assert leases[0].fencing_generation == 1
    with sqlite_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase2_account_leases)
                .where(phase2_account_leases.c.account_id == "parallel-account")
            )
            == 1
        )


def test_run_fenced_holds_database_lock_and_rejects_reentrant_transitions(
    sqlite_engine: Engine,
) -> None:
    primary, primary_clock, _ = coordinator(sqlite_engine, "fenced-account")
    lease = primary.acquire("worker-a")
    primary_clock.advance(timedelta(seconds=1))
    independent, independent_clock, _ = coordinator(
        sqlite_engine,
        "fenced-account",
        clock=MutableClock(BASE + timedelta(seconds=1)),
    )
    entered = threading.Event()
    finish = threading.Event()
    release_started = threading.Event()

    def effect(_receipt: AccountFenceReceipt) -> str:
        with pytest.raises(AccountLeaseConflict, match="during a fenced broker effect"):
            primary.release(lease.fence)
        with pytest.raises(AccountLeaseConflict, match="during a fenced broker effect"):
            primary.renew(lease.fence)
        with pytest.raises(AccountLeaseConflict, match="during a fenced broker effect"):
            primary.acquire("worker-a")
        with pytest.raises(AccountLeaseConflict, match="already in progress"):
            primary.run_fenced(lease.fence, lambda _nested: None)
        assert primary.current() == lease
        entered.set()
        if not finish.wait(timeout=10):
            raise TimeoutError("test fenced operation was not released")
        return "completed"

    def competing_release() -> AccountLeaseRelease:
        release_started.set()
        return independent.release(lease.fence)

    with ThreadPoolExecutor(max_workers=2) as executor:
        effect_future = executor.submit(primary.run_fenced, lease.fence, effect)
        assert entered.wait(timeout=10)
        release_future = executor.submit(competing_release)
        assert release_started.wait(timeout=10)
        assert release_future.done() is False
        finish.set()
        assert effect_future.result(timeout=10) == "completed"
        release = release_future.result(timeout=10)

    assert release.fence == lease.fence
    assert independent_clock.instant == BASE + timedelta(seconds=1)
    assert independent.current() is None


def test_authority_policy_and_clock_references_are_immutable(sqlite_engine: Engine) -> None:
    _, _, authority = coordinator(sqlite_engine, "immutable-authority-account")

    with pytest.raises(AttributeError):
        authority.policy = replace(policy(), policy_version="2")  # type: ignore[misc]
    with pytest.raises(AttributeError):
        authority.clock = MutableClock(BASE + timedelta(seconds=1))  # type: ignore[misc]
