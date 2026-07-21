from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
    AccountLease,
    AccountLeaseConflict,
    AccountLeaseOwnershipLost,
    AccountLeasePolicy,
    AccountLeaseRelease,
)
from packages.domain.models import OrderIntent
from packages.domain.walking_thread import WalkingThread
from packages.execution.account_coordinator import (
    FencedBrokerPort,
    InMemoryAccountCoordinator,
    InMemoryAccountCoordinatorAuthority,
)

BASE = datetime(2026, 7, 20, 13, 30, tzinfo=UTC)


@dataclass
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant

    def advance(self, delta: timedelta) -> None:
        self.instant += delta


def policy() -> AccountLeasePolicy:
    return AccountLeasePolicy(
        policy_id="phase2-simulation-coordinator",
        policy_version="1.0.0",
        lease_ttl=timedelta(seconds=30),
        maximum_in_flight_duration=timedelta(seconds=5),
        takeover_safety_interval=timedelta(seconds=10),
    )


def coordinator(
    account_id: str,
) -> tuple[InMemoryAccountCoordinator, MutableClock, InMemoryAccountCoordinatorAuthority]:
    clock = MutableClock(BASE)
    authority = InMemoryAccountCoordinatorAuthority(policy=policy(), clock=clock)
    return (
        InMemoryAccountCoordinator(account_id=account_id, authority=authority),
        clock,
        authority,
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"lease_ttl": timedelta(0)}, "lease_ttl"),
        ({"maximum_in_flight_duration": timedelta(0)}, "maximum_in_flight_duration"),
        ({"takeover_safety_interval": timedelta(seconds=5)}, "must exceed"),
    ],
)
def test_policy_rejects_unsafe_durations(changes: dict[str, object], message: str) -> None:
    values: dict[str, object] = {
        "policy_id": "coordinator-policy",
        "policy_version": "1",
        "lease_ttl": timedelta(seconds=30),
        "maximum_in_flight_duration": timedelta(seconds=5),
        "takeover_safety_interval": timedelta(seconds=10),
    }
    values.update(changes)

    with pytest.raises(AccountCoordinatorError, match=message):
        AccountLeasePolicy(**values)  # type: ignore[arg-type]


def test_lease_and_fence_require_strict_identity_time_and_generation() -> None:
    lease_policy = policy()
    with pytest.raises(AccountCoordinatorError, match="positive integer"):
        AccountLease(
            account_id="strict-account",
            owner_id="owner-a",
            lease_id="lease-a",
            fencing_generation=0,
            acquired_at=BASE,
            heartbeat_at=BASE,
            expires_at=BASE + timedelta(seconds=30),
            policy_sha256=lease_policy.semantic_sha256,
        )
    with pytest.raises(AccountCoordinatorError, match="timezone-aware"):
        AccountLease(
            account_id="strict-account",
            owner_id="owner-a",
            lease_id="lease-a",
            fencing_generation=1,
            acquired_at=BASE.replace(tzinfo=None),
            heartbeat_at=BASE,
            expires_at=BASE + timedelta(seconds=30),
            policy_sha256=lease_policy.semantic_sha256,
        )
    with pytest.raises(TypeError, match="only be created"):
        AccountFenceReceipt(
            fence=AccountFence(
                account_id="strict-account",
                owner_id="owner-a",
                lease_id="lease-a",
                fencing_generation=1,
            ),
            validated_at=BASE,
            valid_until=BASE + timedelta(seconds=30),
            policy_sha256=lease_policy.semantic_sha256,
            lease_sha256="f" * 64,
        )
    with pytest.raises(TypeError, match="only be created"):
        AccountLeaseRelease(
            fence=AccountFence(
                account_id="strict-account",
                owner_id="owner-a",
                lease_id="lease-a",
                fencing_generation=1,
            ),
            released_at=BASE,
            policy_sha256=lease_policy.semantic_sha256,
            lease_sha256="f" * 64,
        )
    with pytest.raises(AccountCoordinatorError, match="positive integer"):
        AccountFence(
            account_id="strict-account",
            owner_id="owner-a",
            lease_id="lease-a",
            fencing_generation=0,
        )


def test_first_acquisition_and_same_owner_retry_are_identical() -> None:
    account_coordinator, _, _ = coordinator("acquisition-account")

    first = account_coordinator.acquire("worker-a")
    retried = account_coordinator.acquire("worker-a")
    receipt = account_coordinator.revalidate(first.fence)

    assert retried == first
    assert account_coordinator.current() == first
    assert first.fencing_generation == 1
    assert first.acquired_at == BASE
    assert first.heartbeat_at == BASE
    assert first.expires_at == BASE + timedelta(seconds=30)
    assert receipt.fence == first.fence
    assert receipt.validated_at == BASE
    assert receipt.valid_until == first.expires_at


def test_parallel_owners_cannot_both_acquire_one_account() -> None:
    account_coordinator, _, _ = coordinator("parallel-acquisition-account")
    start = threading.Barrier(3)

    def acquire(owner_id: str) -> AccountLease | AccountLeaseConflict:
        start.wait(timeout=10)
        try:
            return account_coordinator.acquire(owner_id)
        except AccountLeaseConflict as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(acquire, owner_id) for owner_id in ("worker-a", "worker-b")]
        start.wait(timeout=10)
        results = [future.result(timeout=10) for future in futures]

    leases = [result for result in results if type(result) is AccountLease]
    conflicts = [result for result in results if type(result) is AccountLeaseConflict]
    assert len(leases) == 1
    assert len(conflicts) == 1
    assert account_coordinator.current() == leases[0]


def test_renewal_retains_generation_and_refreshes_receipt_lease_evidence() -> None:
    account_coordinator, clock, _ = coordinator("renewal-account")
    first = account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=10))

    renewed = account_coordinator.renew(first.fence)

    assert renewed.account_id == first.account_id
    assert renewed.owner_id == first.owner_id
    assert renewed.lease_id == first.lease_id
    assert renewed.fencing_generation == first.fencing_generation
    assert renewed.acquired_at == first.acquired_at
    assert renewed.heartbeat_at == BASE + timedelta(seconds=10)
    assert renewed.expires_at == BASE + timedelta(seconds=40)
    assert renewed.semantic_sha256 != first.semantic_sha256
    assert renewed.fence == first.fence
    receipt = account_coordinator.revalidate(first.fence)
    assert receipt.lease_sha256 == renewed.semantic_sha256
    assert receipt.valid_until == renewed.expires_at
    assert account_coordinator.renew(renewed.fence) == renewed


@pytest.mark.parametrize(
    "field_changes",
    [
        {"account_id": "other-account"},
        {"owner_id": "other-owner"},
        {"lease_id": "other-lease"},
        {"fencing_generation": 2},
    ],
)
def test_foreign_or_forged_fence_is_rejected(field_changes: dict[str, object]) -> None:
    account_coordinator, _, _ = coordinator("forged-fence-" + next(iter(field_changes)))
    current = account_coordinator.acquire("worker-a")

    with pytest.raises(AccountLeaseOwnershipLost, match="no longer current"):
        account_coordinator.revalidate(
            replace(current.fence, **field_changes)  # type: ignore[arg-type]
        )


def test_expired_abandoned_lease_blocks_effects_renewal_release_and_takeover() -> None:
    account_coordinator, clock, _ = coordinator("expired-account")
    lease = account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=30))
    called = False

    def effect(_receipt: object) -> None:
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


def test_clean_release_permits_handoff_and_permanently_fences_old_owner() -> None:
    account_coordinator, clock, _ = coordinator("clean-handoff-account")
    first = account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=1))

    release = account_coordinator.release(first.fence)
    assert account_coordinator.release(first.fence) == release
    second = account_coordinator.acquire("worker-b")

    assert release.fence == first.fence
    assert release.released_at == BASE + timedelta(seconds=1)
    assert second.fencing_generation == 2
    assert second.owner_id == "worker-b"
    with pytest.raises(AccountLeaseOwnershipLost, match="no longer current"):
        account_coordinator.revalidate(first.fence)


def test_fenced_operation_prevents_release_from_interleaving() -> None:
    account_coordinator, clock, _ = coordinator("serialized-effect-account")
    lease = account_coordinator.acquire("worker-a")
    entered = threading.Event()
    finish = threading.Event()

    def effect(_receipt: object) -> str:
        entered.set()
        if not finish.wait(timeout=10):
            raise TimeoutError("test effect was not released")
        return "completed"

    clock.advance(timedelta(seconds=1))
    with ThreadPoolExecutor(max_workers=2) as executor:
        effect_future = executor.submit(account_coordinator.run_fenced, lease.fence, effect)
        assert entered.wait(timeout=10)
        release_future = executor.submit(account_coordinator.release, lease.fence)
        assert release_future.done() is False
        finish.set()
        assert effect_future.result(timeout=10) == "completed"
        released = release_future.result(timeout=10)

    assert released.fence == lease.fence
    assert account_coordinator.current() is None


def test_reentrant_transition_is_rejected_until_fenced_effect_finishes() -> None:
    account_coordinator, clock, _ = coordinator("reentrant-effect-account")
    lease = account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=1))
    effect_completed = False

    def effect(_receipt: object) -> None:
        nonlocal effect_completed
        with pytest.raises(AccountLeaseConflict, match="during a fenced broker effect"):
            account_coordinator.release(lease.fence)
        with pytest.raises(AccountLeaseConflict, match="during a fenced broker effect"):
            account_coordinator.renew(lease.fence)
        with pytest.raises(AccountLeaseConflict, match="during a fenced broker effect"):
            account_coordinator.acquire("worker-a")
        with pytest.raises(AccountLeaseConflict, match="already in progress"):
            account_coordinator.run_fenced(lease.fence, lambda _nested: None)
        effect_completed = True

    account_coordinator.run_fenced(lease.fence, effect)

    assert effect_completed is True
    assert account_coordinator.current() == lease


def test_clock_regression_fails_closed() -> None:
    account_coordinator, clock, _ = coordinator("regressing-clock-account")
    account_coordinator.acquire("worker-a")
    clock.advance(timedelta(seconds=-1))

    with pytest.raises(AccountCoordinatorError, match="cannot regress"):
        account_coordinator.current()  # A read does not sample time.
        account_coordinator.acquire("worker-a")


def test_distinct_authority_cannot_open_an_existing_account_state() -> None:
    account_coordinator, _, _ = coordinator("authority-conflict-account")
    account_coordinator.acquire("worker-a")
    other_authority = InMemoryAccountCoordinatorAuthority(
        policy=policy(),
        clock=MutableClock(BASE),
    )

    with pytest.raises(AccountLeaseConflict, match="already owns"):
        InMemoryAccountCoordinator(
            account_id="authority-conflict-account",
            authority=other_authority,
        )


def test_authority_policy_and_clock_references_are_immutable() -> None:
    _, _, authority = coordinator("immutable-authority-account")

    with pytest.raises(AttributeError):
        authority.policy = policy()  # type: ignore[misc]
    with pytest.raises(AttributeError):
        authority.clock = MutableClock(BASE + timedelta(seconds=1))  # type: ignore[misc]


class RecordingBroker:
    def __init__(self) -> None:
        self.calls: list[tuple[OrderIntent, str, str]] = []

    def submit(
        self,
        intent: OrderIntent,
        risk_decision_id: str,
        submission_attempt_id: str,
    ) -> str:
        self.calls.append((intent, risk_decision_id, submission_attempt_id))
        return "submitted"


def test_fenced_broker_holds_authority_across_exact_delegate_call() -> None:
    account_coordinator, clock, _ = coordinator("fenced-broker-account")
    lease = account_coordinator.acquire("worker-a")
    delegate = RecordingBroker()
    broker = FencedBrokerPort(
        coordinator=account_coordinator,
        fence=lease.fence,
        delegate=delegate,
    )
    intent = WalkingThread.run().intent
    clock.advance(timedelta(seconds=1))

    submission = broker.submit(intent, "risk-decision", "submission-attempt")
    assert submission.result == "submitted"
    assert submission.fence_receipt.fence == lease.fence
    assert submission.fence_receipt.lease_sha256 == lease.semantic_sha256
    assert submission.intent_id == intent.intent_id
    assert submission.intent == intent
    assert submission.risk_decision_id == "risk-decision"
    assert submission.submission_attempt_id == "submission-attempt"
    assert delegate.calls == [(intent, "risk-decision", "submission-attempt")]

    account_coordinator.release(lease.fence)
    with pytest.raises(AccountLeaseOwnershipLost, match="no longer current"):
        broker.submit(intent, "risk-decision-2", "submission-attempt-2")
    assert delegate.calls == [(intent, "risk-decision", "submission-attempt")]


@pytest.mark.parametrize(
    ("risk_decision_id", "submission_attempt_id"),
    [(" ", "submission-attempt"), ("risk-decision", " ")],
)
def test_fenced_broker_rejects_malformed_request_before_delegate_effect(
    risk_decision_id: str,
    submission_attempt_id: str,
) -> None:
    account_coordinator, _, _ = coordinator(
        f"malformed-broker-request-{risk_decision_id!r}-{submission_attempt_id!r}"
    )
    lease = account_coordinator.acquire("worker-a")
    delegate = RecordingBroker()
    broker = FencedBrokerPort(
        coordinator=account_coordinator,
        fence=lease.fence,
        delegate=delegate,
    )

    with pytest.raises(AccountCoordinatorError, match="must be non-empty and trimmed"):
        broker.submit(
            WalkingThread.run().intent,
            risk_decision_id,
            submission_attempt_id,
        )

    assert delegate.calls == []
