"""Process-local account lease authority and fence-guarded broker adapter."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TypeVar

from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountCoordinatorPort,
    AccountFence,
    AccountFenceReceipt,
    AccountLease,
    AccountLeaseConflict,
    AccountLeaseOwnershipLost,
    AccountLeasePolicy,
    AccountLeaseRelease,
    _account_fence_receipt,
    _account_lease_release,
)
from packages.domain.clock import Clock
from packages.domain.identifiers import canonical_id
from packages.domain.models import OrderIntent, require_utc
from packages.domain.risk import intent_payload_hash
from packages.execution.ports import BrokerPort

FencedResultT = TypeVar("FencedResultT")


class InMemoryAccountCoordinatorAuthority:
    """Own trusted time and policy for one or more account coordinators."""

    __slots__ = ("_clock", "_identity", "_policy")

    def __init__(self, *, policy: AccountLeasePolicy, clock: Clock) -> None:
        if type(policy) is not AccountLeasePolicy:
            raise AccountCoordinatorError("coordinator authority requires an exact lease policy")
        if not callable(getattr(clock, "now", None)):
            raise AccountCoordinatorError("coordinator authority requires a trusted clock")
        self._policy = policy
        self._clock = clock
        self._identity = object()

    @property
    def policy(self) -> AccountLeasePolicy:
        return self._policy

    @property
    def clock(self) -> Clock:
        return self._clock


class _InMemoryAccountCoordinatorState:
    __slots__ = (
        "account_id",
        "authority_identity",
        "current_lease",
        "effect_in_progress",
        "last_generation",
        "last_observed_at",
        "lock",
        "policy_sha256",
        "releases",
    )

    def __init__(
        self,
        *,
        account_id: str,
        authority: InMemoryAccountCoordinatorAuthority,
    ) -> None:
        self.account_id = account_id
        self.authority_identity = authority._identity
        self.policy_sha256 = authority.policy.semantic_sha256
        self.current_lease: AccountLease | None = None
        self.effect_in_progress = False
        self.last_generation = 0
        self.last_observed_at: datetime | None = None
        self.releases: dict[str, AccountLeaseRelease] = {}
        self.lock = threading.RLock()


_ACCOUNT_COORDINATOR_STATES_LOCK = threading.Lock()
_ACCOUNT_COORDINATOR_STATES: dict[str, _InMemoryAccountCoordinatorState] = {}


class InMemoryAccountCoordinator:
    """Serialize one account's lease transitions and protected operations."""

    __slots__ = ("_authority", "_state")

    def __init__(
        self,
        *,
        account_id: str,
        authority: InMemoryAccountCoordinatorAuthority,
    ) -> None:
        if type(account_id) is not str or not account_id or account_id != account_id.strip():
            raise AccountCoordinatorError("coordinator account ID must be non-empty and trimmed")
        if type(authority) is not InMemoryAccountCoordinatorAuthority:
            raise AccountCoordinatorError("in-memory coordinator requires its exact authority type")
        with _ACCOUNT_COORDINATOR_STATES_LOCK:
            state = _ACCOUNT_COORDINATOR_STATES.get(account_id)
            if state is None:
                state = _InMemoryAccountCoordinatorState(
                    account_id=account_id,
                    authority=authority,
                )
                _ACCOUNT_COORDINATOR_STATES[account_id] = state
            elif (
                state.authority_identity is not authority._identity
                or state.policy_sha256 != authority.policy.semantic_sha256
            ):
                raise AccountLeaseConflict(
                    "an active process-local authority already owns this account"
                )
        self._authority = authority
        self._state = state

    @property
    def account_id(self) -> str:
        return self._state.account_id

    def _trusted_now(self) -> datetime:
        instant = self._authority.clock.now()
        if not isinstance(instant, datetime):
            raise AccountCoordinatorError("coordinator clock returned a non-datetime value")
        try:
            require_utc(instant, "coordinator clock instant")
        except ValueError as error:
            raise AccountCoordinatorError(str(error)) from error
        instant = instant.astimezone(UTC)
        prior = self._state.last_observed_at
        if prior is not None and instant < prior:
            raise AccountCoordinatorError("coordinator clock cannot regress")
        self._state.last_observed_at = instant
        return instant

    def _require_exact_fence(self, fence: AccountFence) -> AccountLease:
        if type(fence) is not AccountFence:
            raise AccountLeaseOwnershipLost("coordinator requires an exact AccountFence")
        current = self._state.current_lease
        if current is None or fence != current.fence:
            raise AccountLeaseOwnershipLost("account fence is no longer current")
        return current

    def _receipt(self, fence: AccountFence, now: datetime) -> AccountFenceReceipt:
        current = self._require_exact_fence(fence)
        if now >= current.expires_at:
            raise AccountLeaseOwnershipLost("account coordinator lease has expired")
        return _account_fence_receipt(
            fence=fence,
            validated_at=now,
            valid_until=current.expires_at,
            policy_sha256=self._authority.policy.semantic_sha256,
            lease_sha256=current.semantic_sha256,
        )

    def _require_no_effect_transition(self) -> None:
        if self._state.effect_in_progress:
            raise AccountLeaseConflict(
                "account lease cannot transition during a fenced broker effect"
            )

    def acquire(self, owner_id: str) -> AccountLease:
        if type(owner_id) is not str or not owner_id or owner_id != owner_id.strip():
            raise AccountCoordinatorError("coordinator owner ID must be non-empty and trimmed")
        with self._state.lock:
            self._require_no_effect_transition()
            now = self._trusted_now()
            current = self._state.current_lease
            if current is not None:
                if now >= current.expires_at:
                    raise AccountLeaseOwnershipLost(
                        "expired coordinator ownership requires durable reconciliation takeover"
                    )
                if current.owner_id == owner_id:
                    return current
                raise AccountLeaseConflict("account already has an active coordinator owner")
            generation = self._state.last_generation + 1
            lease = AccountLease(
                account_id=self.account_id,
                owner_id=owner_id,
                lease_id=canonical_id(
                    "account-coordinator-lease",
                    self.account_id,
                    generation,
                    owner_id,
                    now,
                    self._authority.policy.semantic_sha256,
                ),
                fencing_generation=generation,
                revision_number=1,
                previous_lease_sha256=None,
                acquired_at=now,
                heartbeat_at=now,
                expires_at=now + self._authority.policy.lease_ttl,
                policy_sha256=self._authority.policy.semantic_sha256,
            )
            self._state.current_lease = lease
            self._state.last_generation = generation
            return lease

    def current(self) -> AccountLease | None:
        with self._state.lock:
            return self._state.current_lease

    def renew(self, fence: AccountFence) -> AccountLease:
        with self._state.lock:
            self._require_no_effect_transition()
            current = self._require_exact_fence(fence)
            now = self._trusted_now()
            if now >= current.expires_at:
                raise AccountLeaseOwnershipLost("expired coordinator lease cannot be renewed")
            if now == current.heartbeat_at:
                return current
            expires_at = now + self._authority.policy.lease_ttl
            if expires_at <= current.expires_at:
                raise AccountCoordinatorError("lease renewal must extend the current expiry")
            renewed = AccountLease(
                account_id=current.account_id,
                owner_id=current.owner_id,
                lease_id=current.lease_id,
                fencing_generation=current.fencing_generation,
                revision_number=current.revision_number + 1,
                previous_lease_sha256=current.semantic_sha256,
                acquired_at=current.acquired_at,
                heartbeat_at=now,
                expires_at=expires_at,
                policy_sha256=current.policy_sha256,
            )
            self._state.current_lease = renewed
            return renewed

    def revalidate(self, fence: AccountFence) -> AccountFenceReceipt:
        """Return point-in-time evidence; use ``run_fenced`` for side effects."""

        with self._state.lock:
            now = self._trusted_now()
            return self._receipt(fence, now)

    def run_fenced(
        self,
        fence: AccountFence,
        operation: Callable[[AccountFenceReceipt], FencedResultT],
    ) -> FencedResultT:
        if not callable(operation):
            raise AccountCoordinatorError("fenced operation must be callable")
        with self._state.lock:
            if self._state.effect_in_progress:
                raise AccountLeaseConflict("a fenced broker effect is already in progress")
            now = self._trusted_now()
            receipt = self._receipt(fence, now)
            self._state.effect_in_progress = True
            try:
                return operation(receipt)
            finally:
                self._state.effect_in_progress = False

    def release(self, fence: AccountFence) -> AccountLeaseRelease:
        with self._state.lock:
            prior_release = self._state.releases.get(fence.semantic_sha256)
            if prior_release is not None:
                return prior_release
            self._require_no_effect_transition()
            now = self._trusted_now()
            current = self._require_exact_fence(fence)
            self._receipt(fence, now)
            release = _account_lease_release(
                fence=fence,
                released_at=now,
                policy_sha256=self._authority.policy.semantic_sha256,
                lease_sha256=current.semantic_sha256,
            )
            self._state.releases[fence.semantic_sha256] = release
            self._state.current_lease = None
            return release


@dataclass(frozen=True, slots=True)
class _FencedBrokerRequest:
    intent: OrderIntent
    intent_payload_sha256: str
    risk_decision_id: str
    submission_attempt_id: str

    def __post_init__(self) -> None:
        if type(self.intent) is not OrderIntent:
            raise AccountCoordinatorError("fenced broker submission requires an exact OrderIntent")
        if self.intent_payload_sha256 != intent_payload_hash(self.intent):
            raise AccountCoordinatorError("fenced broker intent payload digest conflicts")
        for value, field_name in (
            (self.risk_decision_id, "fenced submission risk decision ID"),
            (self.submission_attempt_id, "fenced submission attempt ID"),
        ):
            if type(value) is not str or not value or value != value.strip():
                raise AccountCoordinatorError(f"{field_name} must be non-empty and trimmed")


@dataclass(frozen=True, slots=True, init=False)
class FencedBrokerSubmission[ResultT]:
    """Immutable broker result bound to the fence checked for its submission."""

    fence_receipt: AccountFenceReceipt
    intent: OrderIntent
    intent_payload_sha256: str
    risk_decision_id: str
    submission_attempt_id: str
    result: ResultT

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("FencedBrokerSubmission can only be created by FencedBrokerPort")

    def _validate(self) -> None:
        self.fence_receipt._validate()
        if type(self.intent) is not OrderIntent:
            raise AccountCoordinatorError("fenced submission requires an exact OrderIntent")
        if self.intent_payload_sha256 != intent_payload_hash(self.intent):
            raise AccountCoordinatorError("fenced submission intent payload digest conflicts")
        for value, field_name in (
            (self.risk_decision_id, "fenced submission risk decision ID"),
            (self.submission_attempt_id, "fenced submission attempt ID"),
        ):
            if type(value) is not str or not value or value != value.strip():
                raise AccountCoordinatorError(f"{field_name} must be non-empty and trimmed")
        if (
            type(self.intent_payload_sha256) is not str
            or len(self.intent_payload_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.intent_payload_sha256)
        ):
            raise AccountCoordinatorError(
                "fenced submission intent payload must be a lowercase SHA-256 digest"
            )

    @property
    def intent_id(self) -> str:
        return self.intent.intent_id


def _fenced_broker_submission[ResultT](
    *,
    receipt: AccountFenceReceipt,
    request: _FencedBrokerRequest,
    result: ResultT,
) -> FencedBrokerSubmission[ResultT]:
    submission = object.__new__(FencedBrokerSubmission)
    for field_name, value in (
        ("fence_receipt", receipt),
        ("intent", request.intent),
        ("intent_payload_sha256", request.intent_payload_sha256),
        ("risk_decision_id", request.risk_decision_id),
        ("submission_attempt_id", request.submission_attempt_id),
        ("result", result),
    ):
        object.__setattr__(submission, field_name, value)
    submission._validate()
    return submission


class FencedBrokerPort[ResultT]:
    """Hold the account lock across one exact broker submission call."""

    __slots__ = ("_coordinator", "_delegate", "_fence")

    def __init__(
        self,
        *,
        coordinator: AccountCoordinatorPort,
        fence: AccountFence,
        delegate: BrokerPort[ResultT],
    ) -> None:
        if type(fence) is not AccountFence:
            raise AccountCoordinatorError("fenced broker requires an exact AccountFence")
        if coordinator.account_id != fence.account_id:
            raise AccountCoordinatorError("fenced broker account does not match its fence")
        self._coordinator = coordinator
        self._fence = fence
        self._delegate = delegate

    @property
    def fence(self) -> AccountFence:
        return self._fence

    def submit(
        self,
        intent: OrderIntent,
        risk_decision_id: str,
        submission_attempt_id: str,
    ) -> FencedBrokerSubmission[ResultT]:
        if type(intent) is not OrderIntent:
            raise AccountCoordinatorError("fenced broker submission requires an exact OrderIntent")
        request = _FencedBrokerRequest(
            intent=intent,
            intent_payload_sha256=intent_payload_hash(intent),
            risk_decision_id=risk_decision_id,
            submission_attempt_id=submission_attempt_id,
        )

        def operation(receipt: AccountFenceReceipt) -> FencedBrokerSubmission[ResultT]:
            result = self._delegate.submit(
                request.intent,
                request.risk_decision_id,
                request.submission_attempt_id,
            )
            return _fenced_broker_submission(
                receipt=receipt,
                request=request,
                result=result,
            )

        return self._coordinator.run_fenced(self._fence, operation)
