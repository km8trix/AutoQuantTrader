"""Durable pre-effect lifecycle contracts for supervised strategy invocations.

The claim is intentionally narrower than an execution authorization.  It
allows exactly one caller that received a newly committed claim to invoke the
injected strategy runner.  Reloading a retained claim never authorizes another
subprocess start.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.strategy_supervision import (
    STRATEGY_DECISION_DEADLINE_MICROSECONDS,
    STRATEGY_SUBPROCESS_CLEANUP_MICROSECONDS,
    StrategyInvocation,
    StrategySupervisionOutcome,
    StrategySupervisionResult,
)

STRATEGY_INVOCATION_LIFECYCLE_CONTRACT_VERSION = "phase5c-strategy-invocation-lifecycle-v1"

# A winning claim holder has one second to reach the child-process start
# boundary. The subprocess then has its existing five-second hard deadline and
# the local supervisor has three seconds for bounded termination and pipe
# cleanup. A retained claim is not recoverable until all three non-overlapping
# intervals have elapsed. Recovery never starts a child.
STRATEGY_INVOCATION_START_DEADLINE_MICROSECONDS = 1_000_000
STRATEGY_INVOCATION_START_DEADLINE_INTERVAL = timedelta(
    microseconds=STRATEGY_INVOCATION_START_DEADLINE_MICROSECONDS
)
STRATEGY_INVOCATION_RECOVERY_MICROSECONDS = (
    STRATEGY_INVOCATION_START_DEADLINE_MICROSECONDS
    + STRATEGY_DECISION_DEADLINE_MICROSECONDS
    + STRATEGY_SUBPROCESS_CLEANUP_MICROSECONDS
)
STRATEGY_INVOCATION_RECOVERY_INTERVAL = timedelta(
    microseconds=STRATEGY_INVOCATION_RECOVERY_MICROSECONDS
)
STRATEGY_INVOCATION_INTERRUPTED_DETAIL_CODE = "supervisor_interrupted_after_durable_claim"

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_START_AUTHORIZATION_SEAL = object()


class StrategyInvocationLifecycleError(ValueError):
    """A strategy invocation claim or lifecycle decision is malformed."""


class StrategyInvocationLifecycleConflict(StrategyInvocationLifecycleError):
    """A stable invocation identity is bound to conflicting lifecycle facts."""


class _StrategyInvocationStartAuthorizationUse(Protocol):
    """Injected runtime edge that owns process identity and atomic one-shot use."""

    def validate(
        self,
        *,
        issuer_identity: object,
        capability_nonce: object,
    ) -> None: ...

    def consume(
        self,
        *,
        issuer_identity: object,
        capability_nonce: object,
    ) -> None: ...


class StrategyInvocationDisposition(StrEnum):
    """The only three states visible to the application workflow."""

    NEW = "new"
    PENDING = "pending"
    FINAL = "final"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class StrategyInvocationClaim:
    """Immutable proof that an exact invocation was claimed before its effect."""

    invocation: StrategyInvocation
    fence_receipt: AccountFenceReceipt
    recoverable_at: datetime

    def __post_init__(self) -> None:
        if type(self.invocation) is not StrategyInvocation:
            raise StrategyInvocationLifecycleError(
                "strategy invocation claim requires an exact invocation"
            )
        if type(self.fence_receipt) is not AccountFenceReceipt:
            raise StrategyInvocationLifecycleError(
                "strategy invocation claim requires an exact fence receipt"
            )
        self.invocation.__post_init__()
        try:
            self.fence_receipt._validate()
        except AccountCoordinatorError as error:
            raise StrategyInvocationLifecycleError(str(error)) from error
        if (
            type(self.recoverable_at) is not datetime
            or self.recoverable_at.tzinfo is None
            or self.recoverable_at.utcoffset() is None
            or self.recoverable_at.utcoffset() != UTC.utcoffset(self.recoverable_at)
        ):
            raise StrategyInvocationLifecycleError(
                "strategy invocation claim recoverable_at must be UTC"
            )
        if self.fence_receipt.fence.account_id != self.invocation.control_scope_id:
            raise StrategyInvocationLifecycleConflict(
                "strategy invocation claim crosses account identities"
            )
        if self.invocation.requested_at > self.fence_receipt.validated_at:
            raise StrategyInvocationLifecycleConflict(
                "strategy invocation claim predates its request"
            )
        expected_recoverable_at = (
            self.fence_receipt.validated_at + STRATEGY_INVOCATION_RECOVERY_INTERVAL
        )
        if self.recoverable_at != expected_recoverable_at:
            raise StrategyInvocationLifecycleConflict(
                "strategy invocation claim has a noncanonical recovery instant"
            )
        if self.recoverable_at >= self.fence_receipt.valid_until:
            raise StrategyInvocationLifecycleConflict(
                "strategy invocation claim lacks a full supervised execution window"
            )

    @property
    def claim_id(self) -> str:
        return canonical_id(
            "strategy-invocation-claim",
            self.invocation.invocation_id,
        )

    @property
    def claimed_at(self) -> datetime:
        return self.fence_receipt.validated_at

    @property
    def account_fence(self) -> AccountFence:
        return self.fence_receipt.fence

    @property
    def start_deadline_at(self) -> datetime:
        return self.claimed_at + STRATEGY_INVOCATION_START_DEADLINE_INTERVAL

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                STRATEGY_INVOCATION_LIFECYCLE_CONTRACT_VERSION,
                "claim",
                self.claim_id,
                self.invocation.semantic_sha256,
                self.fence_receipt.semantic_sha256,
                self.recoverable_at,
                "post_commit_new_envelope_only",
                "repository_process_bound_one_shot_start_permit",
                "strict_one_second_child_start_window",
                "retained_claim_never_authorizes_runner",
                "orphan_recovery_never_starts_runner",
            )
        )

    @property
    def automatic_rerun_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True, init=False, eq=False)
class StrategyInvocationStartAuthorization:
    """Fresh process-local proof that the newly claimed child may still start."""

    claim: StrategyInvocationClaim
    fence_receipt: AccountFenceReceipt
    _issuer_identity: object = field(repr=False)
    _capability_nonce: object = field(repr=False)
    _use: _StrategyInvocationStartAuthorizationUse = field(repr=False)
    _seal: object = field(repr=False)

    def __init__(self) -> None:
        raise TypeError(
            "StrategyInvocationStartAuthorization is issued by the durable claim repository"
        )

    def __post_init__(self) -> None:
        if type(self.claim) is not StrategyInvocationClaim:
            raise StrategyInvocationLifecycleError(
                "strategy start authorization requires an exact claim"
            )
        if type(self.fence_receipt) is not AccountFenceReceipt:
            raise StrategyInvocationLifecycleError(
                "strategy start authorization requires an exact fence receipt"
            )
        if (
            self._seal is not _START_AUTHORIZATION_SEAL
            or self._issuer_identity is None
            or self._capability_nonce is None
            or not callable(getattr(self._use, "validate", None))
            or not callable(getattr(self._use, "consume", None))
        ):
            raise StrategyInvocationLifecycleError(
                "strategy start authorization lacks its process-local seal"
            )
        self._use.validate(
            issuer_identity=self._issuer_identity,
            capability_nonce=self._capability_nonce,
        )
        self.claim.__post_init__()
        try:
            self.fence_receipt._validate()
        except AccountCoordinatorError as error:
            raise StrategyInvocationLifecycleError(str(error)) from error
        if self.fence_receipt.fence != self.claim.account_fence:
            raise StrategyInvocationLifecycleConflict(
                "strategy start authorization crosses claim-fence identities"
            )
        if (
            self.fence_receipt.validated_at < self.claim.claimed_at
            or self.fence_receipt.validated_at >= self.claim.start_deadline_at
            or self.claim.recoverable_at >= self.fence_receipt.valid_until
        ):
            raise StrategyInvocationLifecycleConflict(
                "strategy start authorization is outside the claim execution window"
            )

    @property
    def authorized_at(self) -> datetime:
        return self.fence_receipt.validated_at

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                STRATEGY_INVOCATION_LIFECYCLE_CONTRACT_VERSION,
                "start_authorization",
                self.claim.semantic_sha256,
                self.fence_receipt.semantic_sha256,
                self.claim.recoverable_at,
                "sealed_repository_issued_authorization",
                "repository_process_bound_atomic_one_shot_runner_use",
                "runner_must_enforce_strict_start_deadline",
                "single_absolute_monotonic_decision_cleanup_deadline",
            )
        )

    def require_start_at(self, started_at: datetime) -> None:
        if (
            type(started_at) is not datetime
            or started_at.tzinfo is None
            or started_at.utcoffset() is None
            or started_at.utcoffset() != UTC.utcoffset(started_at)
        ):
            raise StrategyInvocationLifecycleError("strategy start time must be UTC")
        if started_at < self.authorized_at or started_at >= self.claim.start_deadline_at:
            raise StrategyInvocationLifecycleConflict(
                "strategy process start is outside its fresh authorization window"
            )

    def consume_for_runner_start(self) -> None:
        """Irrevocably consume authority before any fallible runner preparation."""

        self.__post_init__()
        self._use.consume(
            issuer_identity=self._issuer_identity,
            capability_nonce=self._capability_nonce,
        )

    @property
    def automatic_rerun_authorized(self) -> bool:
        return False


def _strategy_invocation_start_authorization(
    claim: StrategyInvocationClaim,
    *,
    fence_receipt: AccountFenceReceipt,
    issuer_identity: object,
    capability_nonce: object,
    use: _StrategyInvocationStartAuthorizationUse,
) -> StrategyInvocationStartAuthorization:
    if type(claim) is not StrategyInvocationClaim:
        raise StrategyInvocationLifecycleError(
            "strategy start authorization requires an exact claim"
        )
    if (
        issuer_identity is None
        or capability_nonce is None
        or not callable(getattr(use, "validate", None))
        or not callable(getattr(use, "consume", None))
    ):
        raise StrategyInvocationLifecycleError(
            "strategy start authorization requires a process-local capability"
        )
    value = object.__new__(StrategyInvocationStartAuthorization)
    object.__setattr__(value, "claim", claim)
    object.__setattr__(value, "fence_receipt", fence_receipt)
    object.__setattr__(value, "_issuer_identity", issuer_identity)
    object.__setattr__(value, "_capability_nonce", capability_nonce)
    object.__setattr__(value, "_use", use)
    object.__setattr__(value, "_seal", _START_AUTHORIZATION_SEAL)
    value.__post_init__()
    return value


@dataclass(frozen=True, slots=True)
class StrategyInvocationNewClaim:
    """The winning NEW claim plus its non-durable, one-shot start capability."""

    claim: StrategyInvocationClaim
    start_capability: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.claim) is not StrategyInvocationClaim:
            raise StrategyInvocationLifecycleError("new strategy claim requires an exact claim")
        if self.start_capability is None:
            raise StrategyInvocationLifecycleError(
                "new strategy claim requires a process-local start capability"
            )
        self.claim.__post_init__()

    @property
    def disposition(self) -> StrategyInvocationDisposition:
        return StrategyInvocationDisposition.NEW

    @property
    def result(self) -> None:
        return None

    @property
    def runner_call_authorized(self) -> bool:
        return True

    @property
    def automatic_rerun_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class StrategyInvocationLifecycleDecision:
    """Authenticated current state returned by a durable claim repository."""

    claim: StrategyInvocationClaim
    disposition: StrategyInvocationDisposition
    result: StrategySupervisionResult | None

    def __post_init__(self) -> None:
        if type(self.claim) is not StrategyInvocationClaim:
            raise StrategyInvocationLifecycleError(
                "strategy lifecycle decision requires an exact claim"
            )
        if type(self.disposition) is not StrategyInvocationDisposition:
            raise StrategyInvocationLifecycleError(
                "strategy lifecycle decision disposition is unsupported"
            )
        self.claim.__post_init__()
        if self.disposition is StrategyInvocationDisposition.NEW:
            raise StrategyInvocationLifecycleError(
                "NEW strategy authority requires an opaque winning-claim envelope"
            )
        if self.disposition is StrategyInvocationDisposition.FINAL:
            if type(self.result) is not StrategySupervisionResult:
                raise StrategyInvocationLifecycleError(
                    "final strategy lifecycle decision requires an exact result"
                )
            self.result.__post_init__()
            if (
                self.result.invocation_id != self.claim.invocation.invocation_id
                or self.result.invocation_sha256 != self.claim.invocation.semantic_sha256
                or self.result.started_at < self.claim.fence_receipt.validated_at
                or self.result.completed_at > self.claim.recoverable_at
                or (
                    self.result.completed_at == self.claim.recoverable_at
                    and self.result != interrupted_strategy_supervision_result(self.claim)
                )
            ):
                raise StrategyInvocationLifecycleConflict(
                    "strategy lifecycle result crosses invocation or claim-window facts"
                )
        elif self.result is not None:
            raise StrategyInvocationLifecycleError(
                "non-final strategy lifecycle decision cannot carry a result"
            )

    @property
    def runner_call_authorized(self) -> bool:
        return False

    @property
    def automatic_rerun_authorized(self) -> bool:
        return False


def interrupted_strategy_supervision_result(
    claim: StrategyInvocationClaim,
) -> StrategySupervisionResult:
    """Return the one deterministic fail-closed result for an orphaned claim.

    Whether a child was spawned cannot be proven after the supervisor process
    disappears.  ``process_started=False`` therefore means that no process-start
    observation survived the lifecycle boundary; it does not assert that a
    child never existed.  The result does not infer an exit status or retain
    any untrusted output.
    """

    if type(claim) is not StrategyInvocationClaim:
        raise StrategyInvocationLifecycleError(
            "strategy interruption classification requires an exact claim"
        )
    claim.__post_init__()
    result = StrategySupervisionResult(
        invocation_id=claim.invocation.invocation_id,
        invocation_sha256=claim.invocation.semantic_sha256,
        outcome=StrategySupervisionOutcome.CRASH,
        started_at=claim.fence_receipt.validated_at,
        completed_at=claim.recoverable_at,
        elapsed_microseconds=STRATEGY_INVOCATION_RECOVERY_MICROSECONDS,
        process_started=False,
        exit_code=None,
        stdout_bytes=0,
        stdout_sha256=EMPTY_SHA256,
        stderr_bytes=0,
        stderr_sha256=EMPTY_SHA256,
        detail_code=STRATEGY_INVOCATION_INTERRUPTED_DETAIL_CODE,
        response=None,
    )
    result.__post_init__()
    return result


__all__ = [
    "EMPTY_SHA256",
    "STRATEGY_INVOCATION_INTERRUPTED_DETAIL_CODE",
    "STRATEGY_INVOCATION_LIFECYCLE_CONTRACT_VERSION",
    "STRATEGY_INVOCATION_RECOVERY_INTERVAL",
    "STRATEGY_INVOCATION_RECOVERY_MICROSECONDS",
    "STRATEGY_INVOCATION_START_DEADLINE_INTERVAL",
    "STRATEGY_INVOCATION_START_DEADLINE_MICROSECONDS",
    "StrategyInvocationClaim",
    "StrategyInvocationDisposition",
    "StrategyInvocationLifecycleConflict",
    "StrategyInvocationLifecycleDecision",
    "StrategyInvocationLifecycleError",
    "StrategyInvocationNewClaim",
    "StrategyInvocationStartAuthorization",
    "interrupted_strategy_supervision_result",
]
