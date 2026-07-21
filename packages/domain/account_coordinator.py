"""Immutable account-coordinator lease and fencing contracts."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, TypeVar

from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc

ACCOUNT_COORDINATOR_CONTRACT_VERSION = "phase2-account-coordinator-v1"
FencedResultT = TypeVar("FencedResultT")


class AccountCoordinatorError(ValueError):
    """Raised when coordinator evidence is malformed or cannot be honored."""


class AccountLeaseConflict(AccountCoordinatorError):
    """Raised when an account already belongs to another coordinator authority."""


class AccountLeaseOwnershipLost(AccountCoordinatorError):
    """Raised when a lease or fence is no longer the current account authority."""


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise AccountCoordinatorError(f"{field_name} must be a non-empty, trimmed string")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AccountCoordinatorError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AccountCoordinatorError(str(error)) from error


def _duration_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


@dataclass(frozen=True, slots=True)
class AccountLeasePolicy:
    """Versioned timing policy for one process-local coordinator authority."""

    policy_id: str
    policy_version: str
    lease_ttl: timedelta
    maximum_in_flight_duration: timedelta
    takeover_safety_interval: timedelta

    def __post_init__(self) -> None:
        _require_text(self.policy_id, "coordinator policy ID")
        _require_text(self.policy_version, "coordinator policy version")
        for field_name in (
            "lease_ttl",
            "maximum_in_flight_duration",
            "takeover_safety_interval",
        ):
            value = getattr(self, field_name)
            if type(value) is not timedelta or value <= timedelta(0):
                raise AccountCoordinatorError(f"{field_name} must be a positive exact timedelta")
        if self.takeover_safety_interval <= self.maximum_in_flight_duration:
            raise AccountCoordinatorError(
                "takeover_safety_interval must exceed maximum_in_flight_duration"
            )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ACCOUNT_COORDINATOR_CONTRACT_VERSION,
                "lease_policy",
                self.policy_id,
                self.policy_version,
                _duration_microseconds(self.lease_ttl),
                _duration_microseconds(self.maximum_in_flight_duration),
                _duration_microseconds(self.takeover_safety_interval),
            )
        )


@dataclass(frozen=True, slots=True)
class AccountFence:
    """Stable capability for one owner and monotonically fenced lease."""

    account_id: str
    owner_id: str
    lease_id: str
    fencing_generation: int

    def __post_init__(self) -> None:
        _require_text(self.account_id, "fence account ID")
        _require_text(self.owner_id, "fence owner ID")
        _require_text(self.lease_id, "fence lease ID")
        if type(self.fencing_generation) is not int or self.fencing_generation <= 0:
            raise AccountCoordinatorError("fencing_generation must be a positive integer")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ACCOUNT_COORDINATOR_CONTRACT_VERSION,
                "fence",
                self.account_id,
                self.owner_id,
                self.lease_id,
                self.fencing_generation,
            )
        )


@dataclass(frozen=True, slots=True)
class AccountLease:
    """One immutable revision of a renewable account-coordinator lease."""

    account_id: str
    owner_id: str
    lease_id: str
    fencing_generation: int
    acquired_at: datetime
    heartbeat_at: datetime
    expires_at: datetime
    policy_sha256: str

    def __post_init__(self) -> None:
        _require_text(self.account_id, "lease account ID")
        _require_text(self.owner_id, "lease owner ID")
        _require_text(self.lease_id, "lease ID")
        if type(self.fencing_generation) is not int or self.fencing_generation <= 0:
            raise AccountCoordinatorError("fencing_generation must be a positive integer")
        _require_utc(self.acquired_at, "lease acquired_at")
        _require_utc(self.heartbeat_at, "lease heartbeat_at")
        _require_utc(self.expires_at, "lease expires_at")
        if self.heartbeat_at < self.acquired_at:
            raise AccountCoordinatorError("lease heartbeat cannot precede acquisition")
        if self.expires_at <= self.heartbeat_at:
            raise AccountCoordinatorError("lease expiry must follow its heartbeat")
        _require_sha256(self.policy_sha256, "lease policy_sha256")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ACCOUNT_COORDINATOR_CONTRACT_VERSION,
                "lease",
                self.account_id,
                self.owner_id,
                self.lease_id,
                self.fencing_generation,
                self.acquired_at,
                self.heartbeat_at,
                self.expires_at,
                self.policy_sha256,
            )
        )

    @property
    def fence(self) -> AccountFence:
        return AccountFence(
            account_id=self.account_id,
            owner_id=self.owner_id,
            lease_id=self.lease_id,
            fencing_generation=self.fencing_generation,
        )


@dataclass(frozen=True, slots=True, init=False)
class AccountFenceReceipt:
    """Evidence that the current lease was checked at one trusted instant."""

    fence: AccountFence
    validated_at: datetime
    valid_until: datetime
    policy_sha256: str
    lease_sha256: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AccountFenceReceipt can only be created by a coordinator")

    def _validate(self) -> None:
        if type(self.fence) is not AccountFence:
            raise AccountCoordinatorError("fence receipt requires an exact AccountFence")
        _require_utc(self.validated_at, "fence validated_at")
        _require_utc(self.valid_until, "fence valid_until")
        if self.validated_at >= self.valid_until:
            raise AccountCoordinatorError("fence receipt must be validated before lease expiry")
        _require_sha256(self.policy_sha256, "fence receipt policy_sha256")
        _require_sha256(self.lease_sha256, "fence receipt lease_sha256")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ACCOUNT_COORDINATOR_CONTRACT_VERSION,
                "fence_receipt",
                self.fence.semantic_sha256,
                self.validated_at,
                self.valid_until,
                self.policy_sha256,
                self.lease_sha256,
            )
        )

    @property
    def receipt_id(self) -> str:
        return canonical_id("account-fence-receipt", self.semantic_sha256)


@dataclass(frozen=True, slots=True, init=False)
class AccountLeaseRelease:
    """Explicit clean handoff evidence for an unexpired current lease."""

    fence: AccountFence
    released_at: datetime
    policy_sha256: str
    lease_sha256: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AccountLeaseRelease can only be created by a coordinator")

    def _validate(self) -> None:
        if type(self.fence) is not AccountFence:
            raise AccountCoordinatorError("lease release requires an exact AccountFence")
        _require_utc(self.released_at, "lease released_at")
        _require_sha256(self.policy_sha256, "lease release policy_sha256")
        _require_sha256(self.lease_sha256, "lease release lease_sha256")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ACCOUNT_COORDINATOR_CONTRACT_VERSION,
                "lease_release",
                self.fence.semantic_sha256,
                self.released_at,
                self.policy_sha256,
                self.lease_sha256,
            )
        )

    @property
    def release_id(self) -> str:
        return canonical_id("account-lease-release", self.semantic_sha256)


def _account_fence_receipt(
    *,
    fence: AccountFence,
    validated_at: datetime,
    valid_until: datetime,
    policy_sha256: str,
    lease_sha256: str,
) -> AccountFenceReceipt:
    receipt = object.__new__(AccountFenceReceipt)
    for field_name, value in (
        ("fence", fence),
        ("validated_at", validated_at),
        ("valid_until", valid_until),
        ("policy_sha256", policy_sha256),
        ("lease_sha256", lease_sha256),
    ):
        object.__setattr__(receipt, field_name, value)
    receipt._validate()
    return receipt


def _account_lease_release(
    *,
    fence: AccountFence,
    released_at: datetime,
    policy_sha256: str,
    lease_sha256: str,
) -> AccountLeaseRelease:
    release = object.__new__(AccountLeaseRelease)
    for field_name, value in (
        ("fence", fence),
        ("released_at", released_at),
        ("policy_sha256", policy_sha256),
        ("lease_sha256", lease_sha256),
    ):
        object.__setattr__(release, field_name, value)
    release._validate()
    return release


class AccountCoordinatorPort(Protocol):
    """Account-bound lease authority used before every broker side effect."""

    @property
    def account_id(self) -> str: ...

    def acquire(self, owner_id: str) -> AccountLease: ...

    def current(self) -> AccountLease | None: ...

    def renew(self, fence: AccountFence) -> AccountLease: ...

    def revalidate(self, fence: AccountFence) -> AccountFenceReceipt: ...

    def run_fenced(
        self,
        fence: AccountFence,
        operation: Callable[[AccountFenceReceipt], FencedResultT],
    ) -> FencedResultT: ...

    def release(self, fence: AccountFence) -> AccountLeaseRelease: ...
