"""Pure, non-authorizing broker request-budget contracts.

The values in this module reserve space in a conservative rolling request
window.  They perform no persistence or network I/O and never authorize a
broker transport call.  Callers must separately establish credentials,
account fencing, operation-specific authority, and every other side-effect
precondition.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from itertools import pairwise

from packages.domain.canonical import canonical_json_bytes, canonical_json_text

BROKER_REQUEST_BUDGET_CONTRACT_VERSION = "phase4d-broker-request-budget-v1"
DEFAULT_BROKER_REQUEST_WINDOW = timedelta(seconds=60)
MAX_ACTIVE_PERMITS = 100_000
MAX_DURATION_SECONDS = (1 << 63) - 1

_SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BrokerRequestBudgetError(ValueError):
    """Broker request-budget evidence is malformed or inconsistent."""


class BrokerRequestBudgetExhausted(BrokerRequestBudgetError):
    """The requesting purpose has reached its conservative rolling ceiling."""


class BrokerRequestPermitConflict(BrokerRequestBudgetError):
    """Permit history conflicts with its account-local immutable chain."""


class BrokerRequestPermitExpired(BrokerRequestBudgetError):
    """A permit is not fresh at the requested trusted instant."""


class BrokerRequestPurpose(StrEnum):
    """Closed broker-call purposes ordered into conservative capacity tiers."""

    SUBMISSION = "submission"
    UNKNOWN_LOOKUP = "unknown_lookup"
    CANCEL = "cancel"
    RECONCILIATION = "reconciliation"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(
    value: str,
    field_name: str,
    *,
    maximum: int = 128,
) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise BrokerRequestBudgetError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise BrokerRequestBudgetError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise BrokerRequestBudgetError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_optional_sha256(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_sha256(value, field_name)


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise BrokerRequestBudgetError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise BrokerRequestBudgetError(f"{field_name} must be UTC")


def _duration_seconds(value: timedelta) -> int:
    return value.days * 86_400 + value.seconds


@dataclass(frozen=True, slots=True)
class BrokerRequestBudgetPolicy:
    """Versioned provider/environment policy for one rolling request window."""

    policy_id: str
    policy_version: str
    provider_id: str
    environment: str
    window_duration: timedelta
    permit_ttl: timedelta
    submission_capacity: int
    recovery_capacity: int
    total_capacity: int

    def __post_init__(self) -> None:
        for text_value, field_name in (
            (self.policy_id, "budget policy ID"),
            (self.policy_version, "budget policy version"),
            (self.provider_id, "budget provider ID"),
        ):
            _require_text(text_value, field_name)
        _require_text(self.environment, "budget environment", maximum=32)
        for duration_value, field_name in (
            (self.window_duration, "window_duration"),
            (self.permit_ttl, "permit_ttl"),
        ):
            if type(duration_value) is not timedelta or duration_value <= timedelta(0):
                raise BrokerRequestBudgetError(f"{field_name} must be a positive exact timedelta")
            if duration_value.microseconds:
                raise BrokerRequestBudgetError(
                    f"{field_name} must use exact whole-second precision"
                )
            if _duration_seconds(duration_value) > MAX_DURATION_SECONDS:
                raise BrokerRequestBudgetError(f"{field_name} exceeds signed BIGINT second storage")
        if self.permit_ttl > self.window_duration:
            raise BrokerRequestBudgetError("permit_ttl cannot exceed window_duration")
        for capacity_value, field_name in (
            (self.submission_capacity, "submission_capacity"),
            (self.recovery_capacity, "recovery_capacity"),
            (self.total_capacity, "total_capacity"),
        ):
            if type(capacity_value) is not int or capacity_value <= 0:
                raise BrokerRequestBudgetError(f"{field_name} must be a positive exact integer")
            if capacity_value > MAX_ACTIVE_PERMITS:
                raise BrokerRequestBudgetError(
                    f"{field_name} exceeds the bounded active-permit limit"
                )
        if not (self.submission_capacity < self.recovery_capacity < self.total_capacity):
            raise BrokerRequestBudgetError(
                "capacity tiers must satisfy submission_capacity "
                "< recovery_capacity < total_capacity"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BROKER_REQUEST_BUDGET_CONTRACT_VERSION,
            "policy",
            self.policy_id,
            self.policy_version,
            self.provider_id,
            self.environment,
            _duration_seconds(self.window_duration),
            _duration_seconds(self.permit_ttl),
            self.submission_capacity,
            self.recovery_capacity,
            self.total_capacity,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def capacity_for(self, purpose: BrokerRequestPurpose) -> int:
        """Return the total-active ceiling reserved for ``purpose``."""

        if type(purpose) is not BrokerRequestPurpose:
            raise BrokerRequestBudgetError("budget purpose must be an exact BrokerRequestPurpose")
        if purpose is BrokerRequestPurpose.SUBMISSION:
            return self.submission_capacity
        if purpose is BrokerRequestPurpose.UNKNOWN_LOOKUP:
            return self.recovery_capacity
        return self.total_capacity


@dataclass(frozen=True, slots=True)
class BrokerRequestDemand:
    """Idempotent, offline description of one desired broker request."""

    account_id: str
    idempotency_key: str
    operation: str
    purpose: BrokerRequestPurpose
    correlation_sha256: str
    requested_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.account_id, "demand account ID", maximum=64)
        if (
            type(self.idempotency_key) is not str
            or _SAFE_KEY.fullmatch(self.idempotency_key) is None
        ):
            raise BrokerRequestBudgetError(
                "demand idempotency key must contain 8-128 safe visible characters"
            )
        _require_text(self.operation, "demand operation")
        if type(self.purpose) is not BrokerRequestPurpose:
            raise BrokerRequestBudgetError("demand purpose must be an exact BrokerRequestPurpose")
        _require_sha256(self.correlation_sha256, "demand correlation_sha256")
        _require_utc(self.requested_at, "demand requested_at")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BROKER_REQUEST_BUDGET_CONTRACT_VERSION,
            "demand",
            self.account_id,
            self.idempotency_key,
            self.operation,
            self.purpose,
            self.correlation_sha256,
            self.requested_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def demand_id(self) -> str:
        return _sha256(
            (
                BROKER_REQUEST_BUDGET_CONTRACT_VERSION,
                "demand_identity",
                self.account_id,
                self.idempotency_key,
            )
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class BrokerRequestPermit:
    """A short-lived budget allocation, never broker transport authority."""

    account_id: str
    purpose: BrokerRequestPurpose
    demand_id: str
    demand_sha256: str
    policy_sha256: str
    sequence_number: int
    previous_permit_sha256: str | None
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.account_id, "permit account ID", maximum=64)
        if type(self.purpose) is not BrokerRequestPurpose:
            raise BrokerRequestBudgetError("permit purpose must be an exact BrokerRequestPurpose")
        _require_sha256(self.demand_id, "permit demand ID")
        _require_sha256(self.demand_sha256, "permit demand_sha256")
        _require_sha256(self.policy_sha256, "permit policy_sha256")
        if type(self.sequence_number) is not int or self.sequence_number <= 0:
            raise BrokerRequestBudgetError(
                "permit sequence_number must be a positive exact integer"
            )
        if self.sequence_number == 1:
            if self.previous_permit_sha256 is not None:
                raise BrokerRequestBudgetError("first account permit cannot have a predecessor")
        elif self.previous_permit_sha256 is None:
            raise BrokerRequestBudgetError("subsequent account permit requires a predecessor")
        _require_optional_sha256(
            self.previous_permit_sha256,
            "permit previous_permit_sha256",
        )
        _require_utc(self.issued_at, "permit issued_at")
        _require_utc(self.expires_at, "permit expires_at")
        if self.expires_at <= self.issued_at:
            raise BrokerRequestBudgetError("permit expiry must follow issuance")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BROKER_REQUEST_BUDGET_CONTRACT_VERSION,
            "permit",
            self.account_id,
            self.purpose,
            self.demand_id,
            self.demand_sha256,
            self.policy_sha256,
            self.sequence_number,
            self.previous_permit_sha256,
            self.issued_at,
            self.expires_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def permit_id(self) -> str:
        return _sha256(
            (
                BROKER_REQUEST_BUDGET_CONTRACT_VERSION,
                "permit_identity",
                self.semantic_sha256,
            )
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def transport_authorized(self) -> bool:
        """Budget allocation never confers broker transport authority."""

        return False

    @property
    def refundable(self) -> bool:
        """Issued rolling-window capacity is never refunded."""

        return False

    def is_fresh(self, checked_at: datetime) -> bool:
        """Return whether the permit is usable at a trusted instant."""

        _require_utc(checked_at, "permit checked_at")
        return self.issued_at <= checked_at < self.expires_at


@dataclass(frozen=True, slots=True, init=False)
class BrokerRequestPermitFreshnessReceipt:
    """Secret-free evidence that an exact durable permit was freshly checked."""

    permit_id: str
    permit_sha256: str
    policy_sha256: str
    demand_sha256: str
    checked_at: datetime
    expires_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("BrokerRequestPermitFreshnessReceipt is proof-constructed by a repository")

    def _validate(self) -> None:
        for digest, field_name in (
            (self.permit_id, "freshness receipt permit_id"),
            (self.permit_sha256, "freshness receipt permit_sha256"),
            (self.policy_sha256, "freshness receipt policy_sha256"),
            (self.demand_sha256, "freshness receipt demand_sha256"),
        ):
            _require_sha256(digest, field_name)
        _require_utc(self.checked_at, "freshness receipt checked_at")
        _require_utc(self.expires_at, "freshness receipt expires_at")
        if self.checked_at >= self.expires_at:
            raise BrokerRequestPermitExpired(
                "freshness receipt must be checked before permit expiry"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BROKER_REQUEST_BUDGET_CONTRACT_VERSION,
            "permit_freshness_receipt",
            self.permit_id,
            self.permit_sha256,
            self.policy_sha256,
            self.demand_sha256,
            self.checked_at,
            self.expires_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def receipt_id(self) -> str:
        return _sha256(
            (
                BROKER_REQUEST_BUDGET_CONTRACT_VERSION,
                "permit_freshness_receipt_identity",
                self.semantic_sha256,
            )
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def is_fresh(self) -> bool:
        """Proof construction guarantees freshness at ``checked_at``."""

        return self.checked_at < self.expires_at

    @property
    def transport_authorized(self) -> bool:
        """Fresh budget evidence never confers broker transport authority."""

        return False


def _require_policy_bound_expiry(
    permit: BrokerRequestPermit,
    policy: BrokerRequestBudgetPolicy,
) -> None:
    try:
        expected_expiry = permit.issued_at + policy.permit_ttl
    except OverflowError as error:
        raise BrokerRequestBudgetError("permit expiry exceeds supported datetime bounds") from error
    if permit.expires_at != expected_expiry:
        raise BrokerRequestPermitConflict("permit expiry does not bind the exact budget policy TTL")


def _validate_chain(
    *,
    policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    issued_at: datetime,
    active_permits: tuple[BrokerRequestPermit, ...],
    previous_permit: BrokerRequestPermit | None,
    previous_policy: BrokerRequestBudgetPolicy | None,
) -> None:
    """Validate a repository-supplied complete rolling-window suffix."""

    if type(active_permits) is not tuple:
        raise BrokerRequestPermitConflict("active permits must be an immutable tuple")
    if len(active_permits) > MAX_ACTIVE_PERMITS:
        raise BrokerRequestPermitConflict("active permit history exceeds its bounded limit")
    if any(type(permit) is not BrokerRequestPermit for permit in active_permits):
        raise BrokerRequestPermitConflict(
            "active permit history must contain exact BrokerRequestPermit values"
        )
    if previous_permit is not None and type(previous_permit) is not BrokerRequestPermit:
        raise BrokerRequestPermitConflict("previous permit must be an exact BrokerRequestPermit")

    try:
        lower_bound = issued_at - policy.window_duration
    except OverflowError as error:
        raise BrokerRequestBudgetError(
            "rolling window falls outside supported datetime bounds"
        ) from error
    for permit in active_permits:
        permit.__post_init__()
        if permit.account_id != demand.account_id:
            raise BrokerRequestPermitConflict("active permit history must be account-local")
        if permit.policy_sha256 != policy.semantic_sha256:
            raise BrokerRequestPermitConflict(
                "a budget policy cannot change while its rolling history is active"
            )
        _require_policy_bound_expiry(permit, policy)
        if permit.expires_at < lower_bound or permit.issued_at > issued_at:
            raise BrokerRequestPermitConflict(
                "active permit history falls outside the conservative accounting horizon"
            )

    if tuple(permit.sequence_number for permit in active_permits) != tuple(
        sorted(permit.sequence_number for permit in active_permits)
    ):
        raise BrokerRequestPermitConflict("active permit history must use canonical sequence order")
    if len({permit.sequence_number for permit in active_permits}) != len(active_permits):
        raise BrokerRequestPermitConflict("active permit sequence numbers must be unique")
    for earlier, later in pairwise(active_permits):
        if later.sequence_number != earlier.sequence_number + 1:
            raise BrokerRequestPermitConflict(
                "active permit history must be a contiguous account-local suffix"
            )
        if later.previous_permit_sha256 != earlier.semantic_sha256:
            raise BrokerRequestPermitConflict("active permit history has a conflicting predecessor")

    if previous_permit is None:
        if active_permits:
            raise BrokerRequestPermitConflict(
                "active permit history requires its latest predecessor"
            )
        if previous_policy is not None:
            raise BrokerRequestPermitConflict("an initial permit cannot have a previous policy")
        return

    previous_permit.__post_init__()
    if type(previous_policy) is not BrokerRequestBudgetPolicy:
        raise BrokerRequestPermitConflict("an existing permit requires its exact previous policy")
    previous_policy.__post_init__()
    if previous_permit.account_id != demand.account_id:
        raise BrokerRequestPermitConflict("previous permit must be account-local")
    if previous_permit.policy_sha256 != previous_policy.semantic_sha256:
        raise BrokerRequestPermitConflict("previous policy does not bind the latest account permit")
    _require_policy_bound_expiry(previous_permit, previous_policy)
    if previous_permit.issued_at > issued_at:
        raise BrokerRequestPermitConflict("previous permit cannot be issued in the future")
    if previous_permit.demand_id == demand.demand_id:
        raise BrokerRequestPermitConflict("a demand cannot receive more than one permit")

    if previous_policy.semantic_sha256 != policy.semantic_sha256:
        if active_permits:
            raise BrokerRequestPermitConflict("policy rotation requires an empty rolling history")
        if (
            previous_policy.provider_id != policy.provider_id
            or previous_policy.environment != policy.environment
        ):
            raise BrokerRequestPermitConflict(
                "policy rotation cannot change provider or environment"
            )
        try:
            previous_window_drained_at = (
                previous_permit.expires_at + previous_policy.window_duration
            )
        except OverflowError as error:
            raise BrokerRequestBudgetError(
                "previous rolling window exceeds supported datetime bounds"
            ) from error
        if issued_at <= previous_window_drained_at:
            raise BrokerRequestPermitConflict(
                "policy rotation requires the previous rolling window to drain"
            )
        return

    if active_permits:
        if active_permits[-1] != previous_permit:
            raise BrokerRequestPermitConflict(
                "active permit history must end at the latest account permit"
            )
    elif previous_permit.expires_at >= lower_bound:
        raise BrokerRequestPermitConflict(
            "the conservative accounting horizon cannot omit its latest active permit"
        )


def issue_broker_request_permit(
    *,
    policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    issued_at: datetime,
    active_permits: tuple[BrokerRequestPermit, ...],
    previous_permit: BrokerRequestPermit | None,
    previous_policy: BrokerRequestBudgetPolicy | None,
) -> BrokerRequestPermit:
    """Allocate one rolling-window slot from an authoritative history snapshot.

    The caller remains responsible for making the allocation durable and for
    proving that ``active_permits`` is the complete locked account-local suffix.
    The returned evidence cannot authorize transport and cannot be refunded.
    """

    if type(policy) is not BrokerRequestBudgetPolicy:
        raise BrokerRequestBudgetError(
            "permit issuance requires an exact BrokerRequestBudgetPolicy"
        )
    if type(demand) is not BrokerRequestDemand:
        raise BrokerRequestBudgetError("permit issuance requires an exact BrokerRequestDemand")
    policy.__post_init__()
    demand.__post_init__()
    _require_utc(issued_at, "permit issued_at")
    if issued_at < demand.requested_at:
        raise BrokerRequestBudgetError("permit issuance cannot precede demand")
    _validate_chain(
        policy=policy,
        demand=demand,
        issued_at=issued_at,
        active_permits=active_permits,
        previous_permit=previous_permit,
        previous_policy=previous_policy,
    )

    capacity = policy.capacity_for(demand.purpose)
    if len(active_permits) >= capacity:
        raise BrokerRequestBudgetExhausted(
            f"{demand.purpose.value} rolling request capacity is exhausted"
        )

    sequence_number = 1 if previous_permit is None else previous_permit.sequence_number + 1
    previous_permit_sha256 = None if previous_permit is None else previous_permit.semantic_sha256
    try:
        expires_at = issued_at + policy.permit_ttl
    except OverflowError as error:
        raise BrokerRequestBudgetError("permit expiry exceeds supported datetime bounds") from error
    return BrokerRequestPermit(
        account_id=demand.account_id,
        purpose=demand.purpose,
        demand_id=demand.demand_id,
        demand_sha256=demand.semantic_sha256,
        policy_sha256=policy.semantic_sha256,
        sequence_number=sequence_number,
        previous_permit_sha256=previous_permit_sha256,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def require_fresh_broker_request_permit(
    *,
    permit: BrokerRequestPermit,
    policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    checked_at: datetime,
) -> None:
    """Revalidate one exact budget allocation at a trusted instant.

    Success only proves that budget was allocated and remains fresh.  It does
    not confer credentials, account fencing, or broker transport authority.
    """

    if type(permit) is not BrokerRequestPermit:
        raise BrokerRequestPermitConflict("freshness check requires an exact BrokerRequestPermit")
    if type(policy) is not BrokerRequestBudgetPolicy:
        raise BrokerRequestPermitConflict(
            "freshness check requires an exact BrokerRequestBudgetPolicy"
        )
    if type(demand) is not BrokerRequestDemand:
        raise BrokerRequestPermitConflict("freshness check requires an exact BrokerRequestDemand")
    permit.__post_init__()
    policy.__post_init__()
    demand.__post_init__()
    _require_utc(checked_at, "permit checked_at")
    _require_policy_bound_expiry(permit, policy)
    if (
        permit.account_id != demand.account_id
        or permit.purpose is not demand.purpose
        or permit.demand_id != demand.demand_id
        or permit.demand_sha256 != demand.semantic_sha256
        or permit.policy_sha256 != policy.semantic_sha256
    ):
        raise BrokerRequestPermitConflict("permit does not bind the exact demand and budget policy")
    if not permit.is_fresh(checked_at):
        raise BrokerRequestPermitExpired("broker request permit is not fresh")


def _broker_request_permit_freshness_receipt(
    *,
    permit: BrokerRequestPermit,
    policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    checked_at: datetime,
) -> BrokerRequestPermitFreshnessReceipt:
    """Construct freshness evidence after the caller authenticates provenance."""

    require_fresh_broker_request_permit(
        permit=permit,
        policy=policy,
        demand=demand,
        checked_at=checked_at,
    )
    receipt = object.__new__(BrokerRequestPermitFreshnessReceipt)
    for field_name, value in (
        ("permit_id", permit.permit_id),
        ("permit_sha256", permit.semantic_sha256),
        ("policy_sha256", policy.semantic_sha256),
        ("demand_sha256", demand.semantic_sha256),
        ("checked_at", checked_at),
        ("expires_at", permit.expires_at),
    ):
        object.__setattr__(receipt, field_name, value)
    receipt._validate()
    return receipt
