"""Durable pre-effect claims for supervised strategy invocations."""

from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

import packages.persistence.schema as persistence_schema
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
    _account_fence_receipt,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.clock import Clock
from packages.domain.operational_control import (
    OperationalControlError,
    OperationalControlState,
    OperationalControlTransition,
)
from packages.domain.strategy_invocation_lifecycle import (
    STRATEGY_INVOCATION_LIFECYCLE_CONTRACT_VERSION,
    STRATEGY_INVOCATION_RECOVERY_INTERVAL,
    StrategyInvocationClaim,
    StrategyInvocationDisposition,
    StrategyInvocationLifecycleConflict,
    StrategyInvocationLifecycleDecision,
    StrategyInvocationLifecycleError,
    StrategyInvocationNewClaim,
    StrategyInvocationStartAuthorization,
    _strategy_invocation_start_authorization,
    interrupted_strategy_supervision_result,
)
from packages.domain.strategy_supervision import (
    StrategyInvocation,
    StrategySupervisionError,
    StrategySupervisionResult,
)
from packages.persistence.account_coordinator import (
    _write_transaction,
    account_lease_from_row,
    lock_account_capacity_serialization,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import as_aware_utc
from packages.persistence.operational_control import (
    load_operational_control_head_in_transaction,
)
from packages.persistence.strategy_supervision import (
    _STRATEGY_SUPERVISION_LIFECYCLE_WRITE_AUTHORITY,
    StrategySupervisionPersistenceError,
    StrategySupervisionRecord,
    _invocation_from_payload,
    _invocation_payload,
    _record_from_row,
    _record_statement,
    record_strategy_supervision_in_transaction,
)

STRATEGY_INVOCATION_LIFECYCLE_PERSISTENCE_CONTRACT_VERSION = (
    "phase5c-strategy-invocation-lifecycle-persistence-v1"
)
MAX_STRATEGY_INVOCATION_RECOVERY_PAGE_SIZE = 256

LifecycleRow = Mapping[str, object] | RowMapping
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})


class StrategyInvocationLifecyclePersistenceError(RuntimeError):
    """Durable invocation lifecycle evidence is malformed or unavailable."""


class StrategyInvocationLifecyclePersistenceConflict(StrategyInvocationLifecyclePersistenceError):
    """An immutable invocation lifecycle identity has conflicting evidence."""


class _StrategyInvocationStartPermit:
    """Process-local, repository-bound, one-shot authority for one NEW claim."""

    __slots__ = (
        "_consumed",
        "_issued_pid",
        "_issuer_identity",
        "_lock",
        "claim",
    )

    def __init__(
        self,
        *,
        claim: StrategyInvocationClaim,
        issuer_identity: object,
    ) -> None:
        claim.__post_init__()
        self.claim = claim
        self._issuer_identity = issuer_identity
        self._issued_pid = os.getpid()
        self._lock = threading.Lock()
        self._consumed = False

    def consume(self, *, issuer_identity: object) -> StrategyInvocationClaim:
        """Consume before any clock, lock, SQL, or control operation."""

        with self._lock:
            if self._consumed:
                raise StrategyInvocationLifecyclePersistenceConflict(
                    "strategy start permit was already consumed"
                )
            if issuer_identity is not self._issuer_identity or os.getpid() != self._issued_pid:
                raise StrategyInvocationLifecyclePersistenceConflict(
                    "strategy start permit belongs to another repository process"
                )
            self._consumed = True
        return self.claim


class _StrategyInvocationStartAuthorizationUse:
    """Runtime-owned atomic use state for one repository-issued authorization."""

    __slots__ = (
        "_capability_nonce",
        "_consumed",
        "_issued_pid",
        "_issuer_identity",
        "_lock",
    )

    def __init__(
        self,
        *,
        issuer_identity: object,
        capability_nonce: object,
    ) -> None:
        if issuer_identity is None or capability_nonce is None:
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy start authorization requires a process-local capability"
            )
        self._issuer_identity = issuer_identity
        self._capability_nonce = capability_nonce
        self._issued_pid = os.getpid()
        self._lock = threading.Lock()
        self._consumed = False

    def validate(
        self,
        *,
        issuer_identity: object,
        capability_nonce: object,
    ) -> None:
        if (
            issuer_identity is not self._issuer_identity
            or capability_nonce is not self._capability_nonce
            or os.getpid() != self._issued_pid
        ):
            raise StrategyInvocationLifecycleConflict(
                "strategy start authorization belongs to another repository process"
            )

    def consume(
        self,
        *,
        issuer_identity: object,
        capability_nonce: object,
    ) -> None:
        with self._lock:
            self.validate(
                issuer_identity=issuer_identity,
                capability_nonce=capability_nonce,
            )
            if self._consumed:
                raise StrategyInvocationLifecycleConflict(
                    "strategy start authorization was already consumed"
                )
            self._consumed = True


@dataclass(frozen=True, slots=True)
class StrategyInvocationRecoveryCursor:
    """Exact exclusive cursor for a bounded due-claim scan."""

    recoverable_at: datetime
    claim_id: str

    def __post_init__(self) -> None:
        _require_utc(
            self.recoverable_at,
            "strategy invocation recovery cursor recoverable_at",
        )
        if (
            type(self.claim_id) is not str
            or len(self.claim_id) != 36
            or self.claim_id != self.claim_id.strip()
        ):
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation recovery cursor claim ID must be canonical"
            )


@dataclass(frozen=True, slots=True)
class StrategyInvocationRecoveryPage:
    """One authenticated bounded page of unfinished claims due for recovery."""

    claims: tuple[StrategyInvocationClaim, ...]
    resume_after: StrategyInvocationRecoveryCursor | None

    def __post_init__(self) -> None:
        if (
            type(self.claims) is not tuple
            or len(self.claims) > MAX_STRATEGY_INVOCATION_RECOVERY_PAGE_SIZE
        ):
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation recovery page is not bounded"
            )
        previous: tuple[datetime, str] | None = None
        for claim in self.claims:
            if type(claim) is not StrategyInvocationClaim:
                raise StrategyInvocationLifecyclePersistenceError(
                    "strategy invocation recovery page contains a noncanonical claim"
                )
            claim.__post_init__()
            current = (claim.recoverable_at, claim.claim_id)
            if previous is not None and current <= previous:
                raise StrategyInvocationLifecyclePersistenceConflict(
                    "strategy invocation recovery page is not strictly ordered"
                )
            previous = current
        if self.resume_after is not None:
            if type(self.resume_after) is not StrategyInvocationRecoveryCursor:
                raise StrategyInvocationLifecyclePersistenceError(
                    "strategy invocation recovery page has a noncanonical cursor"
                )
            self.resume_after.__post_init__()
            if not self.claims or (
                self.resume_after.recoverable_at,
                self.resume_after.claim_id,
            ) != (
                self.claims[-1].recoverable_at,
                self.claims[-1].claim_id,
            ):
                raise StrategyInvocationLifecyclePersistenceConflict(
                    "strategy invocation recovery cursor does not bind the page tip"
                )


class SqlAccountFenceValidator(Protocol):
    """Narrow coordinator surface used by claim and finalization transactions."""

    def revalidate_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
        *,
        checked_at: datetime,
    ) -> AccountFenceReceipt: ...


def _claim_table() -> sa.Table:
    value = getattr(
        persistence_schema,
        "phase5_strategy_invocation_claims",
        None,
    )
    if not isinstance(value, sa.Table):
        raise StrategyInvocationLifecyclePersistenceError(
            "strategy invocation claim schema is unavailable"
        )
    return value


def _finalization_table() -> sa.Table:
    value = getattr(
        persistence_schema,
        "phase5_strategy_invocation_finalizations",
        None,
    )
    if not isinstance(value, sa.Table):
        raise StrategyInvocationLifecyclePersistenceError(
            "strategy invocation finalization schema is unavailable"
        )
    return value


def _result_table() -> sa.Table:
    value = getattr(
        persistence_schema,
        "phase5_strategy_supervision_results",
        None,
    )
    if not isinstance(value, sa.Table):
        raise StrategyInvocationLifecyclePersistenceError(
            "strategy supervision result schema is unavailable"
        )
    return value


def _lease_table() -> sa.Table:
    value = getattr(persistence_schema, "phase2_account_leases", None)
    if not isinstance(value, sa.Table):
        raise StrategyInvocationLifecyclePersistenceError("account lease schema is unavailable")
    return value


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_utc(value: datetime, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise StrategyInvocationLifecyclePersistenceError(f"{field_name} must be UTC")
    return value


def _text(row: LifecycleRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise StrategyInvocationLifecyclePersistenceError(
            f"persisted strategy invocation {field_name} must be text"
        )
    return value


def _integer(row: LifecycleRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise StrategyInvocationLifecyclePersistenceError(
            f"persisted strategy invocation {field_name} must be an integer"
        )
    return value


def _datetime(row: LifecycleRow, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise StrategyInvocationLifecyclePersistenceError(
            f"persisted strategy invocation {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _validate_receipt(
    receipt: AccountFenceReceipt,
    *,
    fence: AccountFence,
    checked_at: datetime,
) -> None:
    if type(receipt) is not AccountFenceReceipt:
        raise StrategyInvocationLifecyclePersistenceError(
            "strategy invocation fence validator returned a noncanonical receipt"
        )
    try:
        receipt._validate()
    except AccountCoordinatorError as error:
        raise StrategyInvocationLifecyclePersistenceError(str(error)) from error
    if receipt.fence != fence or receipt.validated_at != checked_at:
        raise StrategyInvocationLifecyclePersistenceConflict(
            "strategy invocation fence receipt conflicts"
        )


def _require_control_readiness(
    connection: Connection,
    account_id: str,
) -> OperationalControlTransition:
    current = load_operational_control_head_in_transaction(connection, account_id)
    if current is None:
        raise StrategyInvocationLifecyclePersistenceError(
            "strategy invocation claim requires operational-control readiness"
        )
    return current


def _claim_values(claim: StrategyInvocationClaim) -> dict[str, object]:
    receipt = claim.fence_receipt
    fence = receipt.fence
    return {
        "claim_id": claim.claim_id,
        "account_id": claim.invocation.control_scope_id,
        "invocation_id": claim.invocation.invocation_id,
        "invocation_sha256": claim.invocation.semantic_sha256,
        "owner_id": fence.owner_id,
        "lease_id": fence.lease_id,
        "fencing_generation": fence.fencing_generation,
        "lease_sha256": receipt.lease_sha256,
        "fence_sha256": fence.semantic_sha256,
        "fence_receipt_sha256": receipt.semantic_sha256,
        "policy_sha256": receipt.policy_sha256,
        "claimed_at": receipt.validated_at,
        "claim_valid_until": receipt.valid_until,
        "recoverable_at": claim.recoverable_at,
        "invocation_payload": _invocation_payload(claim.invocation),
        "semantic_sha256": claim.semantic_sha256,
    }


def _claim_from_row(
    connection: Connection,
    row: LifecycleRow,
) -> StrategyInvocationClaim:
    try:
        invocation = _invocation_from_payload(row["invocation_payload"])
        lease_row = (
            connection.execute(
                sa.select(_lease_table()).where(
                    _lease_table().c.account_id == _text(row, "account_id"),
                    _lease_table().c.fencing_generation == _integer(row, "fencing_generation"),
                    _lease_table().c.lease_sha256 == _text(row, "lease_sha256"),
                )
            )
            .mappings()
            .one_or_none()
        )
        if lease_row is None:
            raise StrategyInvocationLifecyclePersistenceConflict(
                "strategy invocation claim references a missing lease"
            )
        lease = account_lease_from_row(lease_row)
        if (
            lease.fence.owner_id != _text(row, "owner_id")
            or lease.fence.lease_id != _text(row, "lease_id")
            or lease.expires_at != _datetime(row, "claim_valid_until")
            or lease.policy_sha256 != _text(row, "policy_sha256")
        ):
            raise StrategyInvocationLifecyclePersistenceConflict(
                "strategy invocation claim conflicts with its lease"
            )
        receipt = _account_fence_receipt(
            fence=lease.fence,
            validated_at=_datetime(row, "claimed_at"),
            valid_until=lease.expires_at,
            policy_sha256=lease.policy_sha256,
            lease_sha256=lease.semantic_sha256,
        )
        claim = StrategyInvocationClaim(
            invocation=invocation,
            fence_receipt=receipt,
            recoverable_at=_datetime(row, "recoverable_at"),
        )
        expected = _claim_values(claim)
        for field_name, expected_value in expected.items():
            observed = row[field_name]
            if field_name in {
                "claimed_at",
                "claim_valid_until",
                "recoverable_at",
            }:
                if not isinstance(observed, datetime):
                    raise StrategyInvocationLifecyclePersistenceConflict(
                        f"persisted strategy invocation {field_name} conflicts"
                    )
                observed = as_aware_utc(observed)
            if observed != expected_value:
                raise StrategyInvocationLifecyclePersistenceConflict(
                    f"persisted strategy invocation {field_name} conflicts"
                )
        return claim
    except StrategyInvocationLifecyclePersistenceError:
        raise
    except (
        AccountCoordinatorError,
        KeyError,
        StrategyInvocationLifecycleError,
        StrategySupervisionError,
        TypeError,
        ValueError,
    ) as error:
        raise StrategyInvocationLifecyclePersistenceError(
            "persisted strategy invocation claim is malformed"
        ) from error


@dataclass(frozen=True, slots=True)
class StrategyInvocationFinalization:
    """Immutable link from one pre-effect claim to its atomic result record."""

    claim: StrategyInvocationClaim
    supervision_record: StrategySupervisionRecord
    finalized_at: datetime

    def __post_init__(self) -> None:
        if type(self.claim) is not StrategyInvocationClaim:
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation finalization requires an exact claim"
            )
        if type(self.supervision_record) is not StrategySupervisionRecord:
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation finalization requires an exact supervision record"
            )
        self.claim.__post_init__()
        self.supervision_record.__post_init__()
        _require_utc(
            self.finalized_at,
            "strategy invocation finalized_at",
        )
        record = self.supervision_record
        result = record.result
        if (
            record.invocation != self.claim.invocation
            or record.recorded_at != self.finalized_at
            or result.started_at < self.claim.fence_receipt.validated_at
            or result.completed_at > self.claim.recoverable_at
            or (
                result.completed_at == self.claim.recoverable_at
                and result != interrupted_strategy_supervision_result(self.claim)
            )
        ):
            raise StrategyInvocationLifecyclePersistenceConflict(
                "strategy invocation finalization crosses claim or execution-window facts"
            )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                STRATEGY_INVOCATION_LIFECYCLE_PERSISTENCE_CONTRACT_VERSION,
                STRATEGY_INVOCATION_LIFECYCLE_CONTRACT_VERSION,
                "finalization",
                self.claim.semantic_sha256,
                self.supervision_record.semantic_sha256,
                self.finalized_at,
            )
        )


def _finalization_values(
    finalization: StrategyInvocationFinalization,
) -> dict[str, object]:
    claim = finalization.claim
    record = finalization.supervision_record
    return {
        "claim_id": claim.claim_id,
        "claim_sha256": claim.semantic_sha256,
        "account_id": claim.invocation.control_scope_id,
        "invocation_id": claim.invocation.invocation_id,
        "invocation_sha256": claim.invocation.semantic_sha256,
        "result_record_sha256": record.semantic_sha256,
        "finalized_at": finalization.finalized_at,
        "semantic_sha256": finalization.semantic_sha256,
    }


def _claim_statement(
    invocation_id: str,
    *,
    for_update: bool,
) -> sa.Select[tuple[object, ...]]:
    statement = sa.select(_claim_table()).where(_claim_table().c.invocation_id == invocation_id)
    if for_update:
        statement = statement.with_for_update()
    return statement


def _finalization_statement(
    claim_id: str,
    *,
    for_update: bool,
) -> sa.Select[tuple[object, ...]]:
    statement = sa.select(_finalization_table()).where(_finalization_table().c.claim_id == claim_id)
    if for_update:
        statement = statement.with_for_update()
    return statement


def _finalization_from_row(
    connection: Connection,
    claim: StrategyInvocationClaim,
    row: LifecycleRow,
) -> StrategyInvocationFinalization:
    try:
        result_row = (
            connection.execute(
                _record_statement(
                    claim.invocation.invocation_id,
                    for_update=False,
                )
            )
            .mappings()
            .one_or_none()
        )
        if result_row is None:
            raise StrategyInvocationLifecyclePersistenceConflict(
                "strategy invocation finalization references a missing result"
            )
        record = _record_from_row(connection, result_row)
        finalization = StrategyInvocationFinalization(
            claim=claim,
            supervision_record=record,
            finalized_at=_datetime(row, "finalized_at"),
        )
        expected = _finalization_values(finalization)
        for field_name, expected_value in expected.items():
            observed = row[field_name]
            if field_name == "finalized_at":
                if not isinstance(observed, datetime):
                    raise StrategyInvocationLifecyclePersistenceConflict(
                        "persisted strategy invocation finalized_at conflicts"
                    )
                observed = as_aware_utc(observed)
            if observed != expected_value:
                raise StrategyInvocationLifecyclePersistenceConflict(
                    f"persisted strategy invocation finalization {field_name} conflicts"
                )
        return finalization
    except StrategyInvocationLifecyclePersistenceError:
        raise
    except (
        KeyError,
        StrategyInvocationLifecycleError,
        StrategySupervisionError,
        StrategySupervisionPersistenceError,
        TypeError,
        ValueError,
    ) as error:
        raise StrategyInvocationLifecyclePersistenceError(
            "persisted strategy invocation finalization is malformed"
        ) from error


def _decision_for_claim(
    connection: Connection,
    claim: StrategyInvocationClaim,
    *,
    for_update: bool,
) -> StrategyInvocationLifecycleDecision:
    finalization_row = (
        connection.execute(
            _finalization_statement(
                claim.claim_id,
                for_update=for_update,
            )
        )
        .mappings()
        .one_or_none()
    )
    if finalization_row is not None:
        finalization = _finalization_from_row(
            connection,
            claim,
            finalization_row,
        )
        return StrategyInvocationLifecycleDecision(
            claim=claim,
            disposition=StrategyInvocationDisposition.FINAL,
            result=finalization.supervision_record.result,
        )
    orphan_result = connection.scalar(
        sa.select(_result_table().c.invocation_id).where(
            _result_table().c.invocation_id == claim.invocation.invocation_id
        )
    )
    if orphan_result is not None:
        raise StrategyInvocationLifecyclePersistenceConflict(
            "strategy invocation claim has an orphaned supervision result"
        )
    return StrategyInvocationLifecycleDecision(
        claim=claim,
        disposition=StrategyInvocationDisposition.PENDING,
        result=None,
    )


def _insert_finalization(
    connection: Connection,
    *,
    claim: StrategyInvocationClaim,
    record: StrategySupervisionRecord,
) -> StrategyInvocationLifecycleDecision:
    finalization = StrategyInvocationFinalization(
        claim=claim,
        supervision_record=record,
        finalized_at=record.recorded_at,
    )
    try:
        connection.execute(
            sa.insert(_finalization_table()).values(**_finalization_values(finalization))
        )
    except IntegrityError as error:
        raise StrategyInvocationLifecyclePersistenceConflict(
            "strategy invocation finalization conflicts with durable history"
        ) from error
    row = (
        connection.execute(
            _finalization_statement(
                claim.claim_id,
                for_update=False,
            )
        )
        .mappings()
        .one()
    )
    persisted = _finalization_from_row(connection, claim, row)
    if persisted != finalization:
        raise StrategyInvocationLifecyclePersistenceError(
            "strategy invocation finalization failed exact SQL readback"
        )
    return StrategyInvocationLifecycleDecision(
        claim=claim,
        disposition=StrategyInvocationDisposition.FINAL,
        result=record.result,
    )


class SqlStrategyInvocationLifecycleRepository:
    """Claim before runner effect and finalize all failure facts atomically."""

    __slots__ = ("_clock", "_coordinator", "_engine", "_start_issuer_identity")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlAccountFenceValidator,
        clock: Clock,
    ) -> None:
        if not isinstance(engine, Engine):
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation lifecycle requires an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation lifecycle uses an unsupported SQL dialect"
            )
        if not callable(getattr(coordinator, "revalidate_in_transaction", None)):
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation lifecycle requires a SQL fence validator"
            )
        if not callable(getattr(clock, "now", None)):
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation lifecycle requires a trusted clock"
            )
        # Fail at composition time rather than at the first strategy effect.
        _claim_table()
        _finalization_table()
        _result_table()
        _lease_table()
        self._engine = engine
        self._coordinator = coordinator
        self._clock = clock
        self._start_issuer_identity = object()

    @property
    def runtime_store_identity(self) -> int:
        return id(self._engine)

    def _trusted_now(self) -> datetime:
        return _require_utc(
            self._clock.now(),
            "strategy invocation lifecycle trusted clock instant",
        )

    def _locked_fence_receipt(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> tuple[datetime, AccountFenceReceipt]:
        """Sample logical time only after acquiring account serialization."""

        lock_account_capacity_serialization(connection, fence.account_id)
        checked_at = self._trusted_now()
        receipt = self._coordinator.revalidate_in_transaction(
            connection,
            fence,
            checked_at=checked_at,
        )
        _validate_receipt(
            receipt,
            fence=fence,
            checked_at=checked_at,
        )
        return checked_at, receipt

    @staticmethod
    def _validate_request(
        invocation: StrategyInvocation,
        fence: AccountFence,
    ) -> None:
        if type(invocation) is not StrategyInvocation:
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation claim requires an exact invocation"
            )
        if type(fence) is not AccountFence:
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation claim requires an exact account fence"
            )
        invocation.__post_init__()
        fence.__post_init__()
        if invocation.control_scope_id != fence.account_id:
            raise StrategyInvocationLifecyclePersistenceConflict(
                "strategy invocation claim crosses account identities"
            )

    @staticmethod
    def _validate_exact_claim(
        persisted: StrategyInvocationClaim,
        supplied: StrategyInvocationClaim,
    ) -> None:
        if persisted != supplied:
            raise StrategyInvocationLifecyclePersistenceConflict(
                "strategy invocation claim conflicts with durable history"
            )

    def claim(
        self,
        invocation: StrategyInvocation,
        fence: AccountFence,
    ) -> StrategyInvocationNewClaim | StrategyInvocationLifecycleDecision:
        """Commit one claim and issue NEW authority only after SQL commit."""

        self._validate_request(invocation, fence)
        newly_committed: StrategyInvocationClaim | None = None
        try:
            with _write_transaction(self._engine) as connection:
                checked_at, receipt = self._locked_fence_receipt(
                    connection,
                    fence,
                )
                control = _require_control_readiness(
                    connection,
                    invocation.control_scope_id,
                )
                existing_row = (
                    connection.execute(
                        _claim_statement(
                            invocation.invocation_id,
                            for_update=True,
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing_row is not None:
                    existing = _claim_from_row(connection, existing_row)
                    if existing.invocation != invocation:
                        raise StrategyInvocationLifecyclePersistenceConflict(
                            "strategy invocation identity conflicts with its retained claim"
                        )
                    return _decision_for_claim(
                        connection,
                        existing,
                        for_update=True,
                    )
                if control.effective_state is not OperationalControlState.RUNNING:
                    raise StrategyInvocationLifecyclePersistenceError(
                        "new strategy invocation claim requires RUNNING operational control"
                    )
                if checked_at < invocation.requested_at:
                    raise StrategyInvocationLifecyclePersistenceConflict(
                        "strategy invocation claim clock predates its request"
                    )
                orphan_result = connection.scalar(
                    sa.select(_result_table().c.invocation_id).where(
                        _result_table().c.invocation_id == invocation.invocation_id
                    )
                )
                if orphan_result is not None:
                    raise StrategyInvocationLifecyclePersistenceConflict(
                        "strategy invocation already has an unclaimed result"
                    )
                claim = StrategyInvocationClaim(
                    invocation=invocation,
                    fence_receipt=receipt,
                    recoverable_at=(checked_at + STRATEGY_INVOCATION_RECOVERY_INTERVAL),
                )
                try:
                    connection.execute(sa.insert(_claim_table()).values(**_claim_values(claim)))
                except IntegrityError as error:
                    raise StrategyInvocationLifecyclePersistenceConflict(
                        "strategy invocation claim conflicts with durable history"
                    ) from error
                persisted_row = (
                    connection.execute(
                        _claim_statement(
                            invocation.invocation_id,
                            for_update=False,
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = _claim_from_row(connection, persisted_row)
                if persisted != claim:
                    raise StrategyInvocationLifecyclePersistenceError(
                        "strategy invocation claim failed exact SQL readback"
                    )
                newly_committed = persisted
        except StrategyInvocationLifecyclePersistenceError:
            raise
        except (
            AccountCoordinatorError,
            OperationalControlError,
            StrategyInvocationLifecycleError,
            StrategySupervisionError,
        ) as error:
            raise StrategyInvocationLifecyclePersistenceError(str(error)) from error
        if newly_committed is None:
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation claim commit produced no exact claim"
            )
        # Registration happens only after the transaction context has committed.
        # A crash between commit and this process-local issuance loses launch
        # authority safely; the retained claim can only recover.
        permit = _StrategyInvocationStartPermit(
            claim=newly_committed,
            issuer_identity=self._start_issuer_identity,
        )
        return StrategyInvocationNewClaim(
            claim=newly_committed,
            start_capability=permit,
        )

    def authorize_start(
        self,
        start_capability: object,
        fence: AccountFence,
    ) -> StrategyInvocationStartAuthorization | StrategyInvocationLifecycleDecision:
        """Consume NEW-only authority before refreshing the child start.

        The exact winning permit is consumed before every fallible operation.
        Any subsequent failure permanently sacrifices launch authority and
        leaves the retained claim available only to fail-closed recovery.
        """

        if type(start_capability) is not _StrategyInvocationStartPermit:
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy start authorization requires the winning NEW permit"
            )
        claim = start_capability.consume(
            issuer_identity=self._start_issuer_identity,
        )
        claim.__post_init__()
        self._validate_request(claim.invocation, fence)
        if claim.account_fence != fence:
            raise StrategyInvocationLifecyclePersistenceConflict(
                "strategy start authorization requires the claim fence"
            )
        try:
            with _write_transaction(self._engine) as connection:
                authorized_at, receipt = self._locked_fence_receipt(
                    connection,
                    fence,
                )
                control = _require_control_readiness(
                    connection,
                    claim.invocation.control_scope_id,
                )
                row = (
                    connection.execute(
                        _claim_statement(
                            claim.invocation.invocation_id,
                            for_update=True,
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise StrategyInvocationLifecyclePersistenceConflict(
                        "strategy start authorization lacks its durable claim"
                    )
                persisted_claim = _claim_from_row(connection, row)
                self._validate_exact_claim(persisted_claim, claim)
                retained = _decision_for_claim(
                    connection,
                    persisted_claim,
                    for_update=True,
                )
                if retained.disposition is StrategyInvocationDisposition.FINAL:
                    return retained
                if authorized_at >= persisted_claim.recoverable_at:
                    result = interrupted_strategy_supervision_result(persisted_claim)
                    record = record_strategy_supervision_in_transaction(
                        connection,
                        coordinator=self._coordinator,
                        invocation=persisted_claim.invocation,
                        result=result,
                        fence=fence,
                        recorded_at=authorized_at,
                        lifecycle_authority=(_STRATEGY_SUPERVISION_LIFECYCLE_WRITE_AUTHORITY),
                    )
                    return _insert_finalization(
                        connection,
                        claim=persisted_claim,
                        record=record,
                    )
                if authorized_at >= persisted_claim.start_deadline_at:
                    raise StrategyInvocationLifecyclePersistenceError(
                        "strategy start authorization missed its strict start deadline"
                    )
                if control.effective_state is not OperationalControlState.RUNNING:
                    raise StrategyInvocationLifecyclePersistenceError(
                        "strategy start authorization requires RUNNING operational control"
                    )
                return _strategy_invocation_start_authorization(
                    persisted_claim,
                    fence_receipt=receipt,
                    issuer_identity=self._start_issuer_identity,
                    capability_nonce=start_capability,
                    use=_StrategyInvocationStartAuthorizationUse(
                        issuer_identity=self._start_issuer_identity,
                        capability_nonce=start_capability,
                    ),
                )
        except StrategyInvocationLifecyclePersistenceError:
            raise
        except (
            AccountCoordinatorError,
            OperationalControlError,
            StrategyInvocationLifecycleError,
            StrategySupervisionError,
            StrategySupervisionPersistenceError,
        ) as error:
            raise StrategyInvocationLifecyclePersistenceError(str(error)) from error

    def finalize(
        self,
        claim: StrategyInvocationClaim,
        result: StrategySupervisionResult,
        fence: AccountFence,
    ) -> StrategyInvocationLifecycleDecision:
        """Atomically link a timely exact result to its claim and safety effects."""

        if type(claim) is not StrategyInvocationClaim:
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation finalization requires an exact claim"
            )
        if type(result) is not StrategySupervisionResult:
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation finalization requires an exact result"
            )
        claim.__post_init__()
        result.__post_init__()
        self._validate_request(claim.invocation, fence)
        if (
            result.invocation_id != claim.invocation.invocation_id
            or result.invocation_sha256 != claim.invocation.semantic_sha256
            or result.started_at < claim.fence_receipt.validated_at
            or result.completed_at >= claim.recoverable_at
        ):
            raise StrategyInvocationLifecyclePersistenceConflict(
                "strategy invocation result conflicts with its claim"
            )
        try:
            with _write_transaction(self._engine) as connection:
                recorded_at, _ = self._locked_fence_receipt(
                    connection,
                    fence,
                )
                _require_control_readiness(
                    connection,
                    claim.invocation.control_scope_id,
                )
                row = (
                    connection.execute(
                        _claim_statement(
                            claim.invocation.invocation_id,
                            for_update=True,
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise StrategyInvocationLifecyclePersistenceConflict(
                        "strategy invocation finalization lacks its durable claim"
                    )
                persisted_claim = _claim_from_row(connection, row)
                self._validate_exact_claim(persisted_claim, claim)
                retained = _decision_for_claim(
                    connection,
                    claim,
                    for_update=True,
                )
                if retained.disposition is StrategyInvocationDisposition.FINAL:
                    if retained.result != result:
                        raise StrategyInvocationLifecyclePersistenceConflict(
                            "strategy invocation finalization result conflicts"
                        )
                    return retained
                if recorded_at < result.completed_at:
                    raise StrategyInvocationLifecyclePersistenceConflict(
                        "strategy invocation finalization clock predates the result"
                    )
                if recorded_at >= claim.recoverable_at:
                    raise StrategyInvocationLifecyclePersistenceConflict(
                        "strategy invocation result missed its claim finalization window"
                    )
                record = record_strategy_supervision_in_transaction(
                    connection,
                    coordinator=self._coordinator,
                    invocation=claim.invocation,
                    result=result,
                    fence=fence,
                    recorded_at=recorded_at,
                    lifecycle_authority=_STRATEGY_SUPERVISION_LIFECYCLE_WRITE_AUTHORITY,
                )
                return _insert_finalization(
                    connection,
                    claim=claim,
                    record=record,
                )
        except StrategyInvocationLifecyclePersistenceError:
            raise
        except (
            AccountCoordinatorError,
            OperationalControlError,
            StrategyInvocationLifecycleError,
            StrategySupervisionError,
            StrategySupervisionPersistenceError,
        ) as error:
            raise StrategyInvocationLifecyclePersistenceError(str(error)) from error

    def recover(
        self,
        claim: StrategyInvocationClaim,
        fence: AccountFence,
    ) -> StrategyInvocationLifecycleDecision:
        """Classify a safe orphan as CRASH without ever invoking a runner."""

        if type(claim) is not StrategyInvocationClaim:
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation recovery requires an exact claim"
            )
        claim.__post_init__()
        self._validate_request(claim.invocation, fence)
        try:
            with _write_transaction(self._engine) as connection:
                recovered_at, _ = self._locked_fence_receipt(
                    connection,
                    fence,
                )
                _require_control_readiness(
                    connection,
                    claim.invocation.control_scope_id,
                )
                row = (
                    connection.execute(
                        _claim_statement(
                            claim.invocation.invocation_id,
                            for_update=True,
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise StrategyInvocationLifecyclePersistenceConflict(
                        "strategy invocation recovery lacks its durable claim"
                    )
                persisted_claim = _claim_from_row(connection, row)
                self._validate_exact_claim(persisted_claim, claim)
                retained = _decision_for_claim(
                    connection,
                    claim,
                    for_update=True,
                )
                if retained.disposition is StrategyInvocationDisposition.FINAL:
                    return retained
                if recovered_at < claim.recoverable_at:
                    return retained
                result = interrupted_strategy_supervision_result(claim)
                record = record_strategy_supervision_in_transaction(
                    connection,
                    coordinator=self._coordinator,
                    invocation=claim.invocation,
                    result=result,
                    fence=fence,
                    recorded_at=recovered_at,
                    lifecycle_authority=_STRATEGY_SUPERVISION_LIFECYCLE_WRITE_AUTHORITY,
                )
                return _insert_finalization(
                    connection,
                    claim=claim,
                    record=record,
                )
        except StrategyInvocationLifecyclePersistenceError:
            raise
        except (
            AccountCoordinatorError,
            OperationalControlError,
            StrategyInvocationLifecycleError,
            StrategySupervisionError,
            StrategySupervisionPersistenceError,
        ) as error:
            raise StrategyInvocationLifecyclePersistenceError(str(error)) from error

    def load(
        self,
        invocation_id: str,
    ) -> StrategyInvocationLifecycleDecision | None:
        """Load and authenticate one lifecycle without granting runner authority."""

        if (
            type(invocation_id) is not str
            or not invocation_id
            or invocation_id != invocation_id.strip()
        ):
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation lifecycle ID must be non-empty trimmed text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            row = (
                connection.execute(
                    _claim_statement(
                        invocation_id,
                        for_update=False,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            claim = _claim_from_row(connection, row)
            return _decision_for_claim(
                connection,
                claim,
                for_update=False,
            )

    def scan_due_claims(
        self,
        *,
        due_at: datetime,
        page_size: int = MAX_STRATEGY_INVOCATION_RECOVERY_PAGE_SIZE,
        resume_after: StrategyInvocationRecoveryCursor | None = None,
    ) -> StrategyInvocationRecoveryPage:
        """Return one bounded authenticated page of due unfinished claims."""

        due_at = _require_utc(
            due_at,
            "strategy invocation recovery scan due_at",
        )
        if (
            type(page_size) is not int
            or page_size < 1
            or page_size > MAX_STRATEGY_INVOCATION_RECOVERY_PAGE_SIZE
        ):
            raise StrategyInvocationLifecyclePersistenceError(
                "strategy invocation recovery page size is outside its bound"
            )
        if resume_after is not None:
            if type(resume_after) is not StrategyInvocationRecoveryCursor:
                raise StrategyInvocationLifecyclePersistenceError(
                    "strategy invocation recovery scan cursor is noncanonical"
                )
            resume_after.__post_init__()

        claim_table = _claim_table()
        finalization_table = _finalization_table()
        predicates: list[sa.ColumnElement[bool]] = [
            claim_table.c.recoverable_at <= due_at,
            ~sa.exists(
                sa.select(1)
                .select_from(finalization_table)
                .where(finalization_table.c.claim_id == claim_table.c.claim_id)
            ),
        ]
        if resume_after is not None:
            predicates.append(
                sa.or_(
                    claim_table.c.recoverable_at > resume_after.recoverable_at,
                    sa.and_(
                        claim_table.c.recoverable_at == resume_after.recoverable_at,
                        claim_table.c.claim_id > resume_after.claim_id,
                    ),
                )
            )
        statement = (
            sa.select(claim_table)
            .where(*predicates)
            .order_by(
                claim_table.c.recoverable_at,
                claim_table.c.claim_id,
            )
            .limit(page_size + 1)
        )
        with _repeatable_read_transaction(self._engine) as connection:
            rows = connection.execute(statement).mappings().all()
            authenticated: list[StrategyInvocationClaim] = []
            for row in rows:
                claim = _claim_from_row(connection, row)
                decision = _decision_for_claim(
                    connection,
                    claim,
                    for_update=False,
                )
                if decision.disposition is not StrategyInvocationDisposition.PENDING:
                    raise StrategyInvocationLifecyclePersistenceConflict(
                        "strategy invocation recovery scan selected a finalized claim"
                    )
                authenticated.append(claim)
        page_claims = tuple(authenticated[:page_size])
        cursor = (
            StrategyInvocationRecoveryCursor(
                recoverable_at=page_claims[-1].recoverable_at,
                claim_id=page_claims[-1].claim_id,
            )
            if len(authenticated) > page_size
            else None
        )
        return StrategyInvocationRecoveryPage(
            claims=page_claims,
            resume_after=cursor,
        )

    def verify_integrity(self) -> None:
        verify_strategy_invocation_lifecycle_integrity(self._engine)


def _verify_strategy_invocation_lifecycle_integrity(
    connection: Connection,
) -> None:
    if not isinstance(connection, Connection):
        raise StrategyInvocationLifecyclePersistenceError(
            "strategy invocation lifecycle verification requires a Connection"
        )
    if connection.dialect.name not in _SUPPORTED_DIALECTS:
        raise StrategyInvocationLifecyclePersistenceError(
            "strategy invocation lifecycle verification uses an unsupported SQL dialect"
        )
    claims: dict[str, StrategyInvocationClaim] = {}
    for row in connection.execute(
        sa.select(_claim_table()).order_by(
            _claim_table().c.account_id,
            _claim_table().c.claimed_at,
            _claim_table().c.claim_id,
        )
    ).mappings():
        claim = _claim_from_row(connection, row)
        if claim.claim_id in claims:
            raise StrategyInvocationLifecyclePersistenceConflict(
                "strategy invocation claim identity is not unique"
            )
        claims[claim.claim_id] = claim
        _decision_for_claim(
            connection,
            claim,
            for_update=False,
        )
    finalization_rows = connection.execute(
        sa.select(_finalization_table()).order_by(_finalization_table().c.claim_id)
    ).mappings()
    final_invocation_ids: set[str] = set()
    for row in finalization_rows:
        claim_id = _text(row, "claim_id")
        linked_claim = claims.get(claim_id)
        if linked_claim is None:
            raise StrategyInvocationLifecyclePersistenceConflict(
                "strategy invocation finalization has no exact claim"
            )
        finalization = _finalization_from_row(connection, linked_claim, row)
        if finalization.claim.invocation.invocation_id in final_invocation_ids:
            raise StrategyInvocationLifecyclePersistenceConflict(
                "strategy invocation has multiple finalizations"
            )
        final_invocation_ids.add(finalization.claim.invocation.invocation_id)
    result_invocation_ids = set(connection.scalars(sa.select(_result_table().c.invocation_id)))
    if result_invocation_ids != final_invocation_ids:
        raise StrategyInvocationLifecyclePersistenceConflict(
            "strategy supervision results and invocation finalizations are not exact"
        )


def verify_strategy_invocation_lifecycle_integrity(engine: Engine) -> None:
    """Authenticate the complete claim/result lifecycle in one stable snapshot."""

    if not isinstance(engine, Engine):
        raise StrategyInvocationLifecyclePersistenceError(
            "strategy invocation lifecycle verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise StrategyInvocationLifecyclePersistenceError(
            "strategy invocation lifecycle verification uses an unsupported SQL dialect"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_strategy_invocation_lifecycle_integrity(connection)


__all__ = [
    "MAX_STRATEGY_INVOCATION_RECOVERY_PAGE_SIZE",
    "STRATEGY_INVOCATION_LIFECYCLE_PERSISTENCE_CONTRACT_VERSION",
    "SqlStrategyInvocationLifecycleRepository",
    "StrategyInvocationFinalization",
    "StrategyInvocationLifecyclePersistenceConflict",
    "StrategyInvocationLifecyclePersistenceError",
    "StrategyInvocationRecoveryCursor",
    "StrategyInvocationRecoveryPage",
    "verify_strategy_invocation_lifecycle_integrity",
]
