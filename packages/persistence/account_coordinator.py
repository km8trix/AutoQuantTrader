"""Durable SQL account leases and transaction-scoped fencing checks."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Any, TypeVar, cast

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.domain.account_coordinator import (
    ACCOUNT_COORDINATOR_CONTRACT_VERSION,
    AccountCoordinatorError,
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
from packages.domain.canonical import canonical_json_text
from packages.domain.clock import Clock
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc
from packages.persistence.immutable import as_aware_utc
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
)

FencedResultT = TypeVar("FencedResultT")
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})
CoordinatorRow = Mapping[str, object] | RowMapping


def _lease_payload(lease: AccountLease) -> tuple[object, ...]:
    return (
        ACCOUNT_COORDINATOR_CONTRACT_VERSION,
        "lease",
        lease.account_id,
        lease.owner_id,
        lease.lease_id,
        lease.fencing_generation,
        lease.acquired_at,
        lease.heartbeat_at,
        lease.expires_at,
        lease.policy_sha256,
    )


def immutable_account_lease_values(lease: AccountLease) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one lease revision."""

    if type(lease) is not AccountLease:
        raise AccountCoordinatorError("lease persistence requires an exact AccountLease")
    return {
        "lease_sha256": lease.semantic_sha256,
        "account_id": lease.account_id,
        "owner_id": lease.owner_id,
        "lease_id": lease.lease_id,
        "fencing_generation": lease.fencing_generation,
        "acquired_at": lease.acquired_at,
        "heartbeat_at": lease.heartbeat_at,
        "expires_at": lease.expires_at,
        "policy_sha256": lease.policy_sha256,
        "canonical_payload": canonical_json_text(_lease_payload(lease)),
    }


def _required_text(row: CoordinatorRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise AccountCoordinatorError(f"persisted coordinator {field_name} must be a string")
    return value


def _required_integer(row: CoordinatorRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise AccountCoordinatorError(f"persisted coordinator {field_name} must be an integer")
    return value


def _required_datetime(row: CoordinatorRow, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise AccountCoordinatorError(f"persisted coordinator {field_name} must be a datetime")
    return as_aware_utc(value)


def account_lease_from_row(row: CoordinatorRow) -> AccountLease:
    """Strictly decode and authenticate one persisted immutable lease revision."""

    try:
        lease = AccountLease(
            account_id=_required_text(row, "account_id"),
            owner_id=_required_text(row, "owner_id"),
            lease_id=_required_text(row, "lease_id"),
            fencing_generation=_required_integer(row, "fencing_generation"),
            acquired_at=_required_datetime(row, "acquired_at"),
            heartbeat_at=_required_datetime(row, "heartbeat_at"),
            expires_at=_required_datetime(row, "expires_at"),
            policy_sha256=_required_text(row, "policy_sha256"),
        )
        if _required_text(row, "lease_sha256") != lease.semantic_sha256:
            raise AccountCoordinatorError("persisted account lease digest conflicts")
        if _required_text(row, "canonical_payload") != canonical_json_text(_lease_payload(lease)):
            raise AccountCoordinatorError("persisted account lease canonical payload conflicts")
        return lease
    except AccountCoordinatorError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AccountCoordinatorError("persisted account lease is malformed") from error


def _release_payload(release: AccountLeaseRelease) -> tuple[object, ...]:
    return (
        ACCOUNT_COORDINATOR_CONTRACT_VERSION,
        "lease_release",
        release.fence.semantic_sha256,
        release.released_at,
        release.policy_sha256,
        release.lease_sha256,
    )


def immutable_account_lease_release_values(
    release: AccountLeaseRelease,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of a clean release."""

    if type(release) is not AccountLeaseRelease:
        raise AccountCoordinatorError(
            "lease release persistence requires an exact AccountLeaseRelease"
        )
    return {
        "release_id": release.release_id,
        "release_sha256": release.semantic_sha256,
        "account_id": release.fence.account_id,
        "owner_id": release.fence.owner_id,
        "lease_id": release.fence.lease_id,
        "fencing_generation": release.fence.fencing_generation,
        "lease_sha256": release.lease_sha256,
        "released_at": release.released_at,
        "policy_sha256": release.policy_sha256,
        "canonical_payload": canonical_json_text(_release_payload(release)),
    }


def account_lease_release_from_row(row: CoordinatorRow) -> AccountLeaseRelease:
    """Strictly decode and authenticate one persisted clean-release fact."""

    try:
        release = _account_lease_release(
            fence=AccountFence(
                account_id=_required_text(row, "account_id"),
                owner_id=_required_text(row, "owner_id"),
                lease_id=_required_text(row, "lease_id"),
                fencing_generation=_required_integer(row, "fencing_generation"),
            ),
            released_at=_required_datetime(row, "released_at"),
            policy_sha256=_required_text(row, "policy_sha256"),
            lease_sha256=_required_text(row, "lease_sha256"),
        )
        if _required_text(row, "release_id") != release.release_id:
            raise AccountCoordinatorError("persisted account lease release ID conflicts")
        if _required_text(row, "release_sha256") != release.semantic_sha256:
            raise AccountCoordinatorError("persisted account lease release digest conflicts")
        if _required_text(row, "canonical_payload") != canonical_json_text(
            _release_payload(release)
        ):
            raise AccountCoordinatorError(
                "persisted account lease release canonical payload conflicts"
            )
        return release
    except AccountCoordinatorError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AccountCoordinatorError("persisted account lease release is malformed") from error


@dataclass(frozen=True, slots=True)
class _LeaseHead:
    account_id: str
    last_fencing_generation: int
    current_fencing_generation: int | None
    current_lease_sha256: str | None
    updated_at: datetime


def _lease_head_from_row(row: CoordinatorRow) -> _LeaseHead:
    try:
        current_generation = row["current_fencing_generation"]
        current_digest = row["current_lease_sha256"]
        if current_generation is not None and type(current_generation) is not int:
            raise AccountCoordinatorError(
                "persisted current fencing generation must be an integer or null"
            )
        if current_digest is not None and type(current_digest) is not str:
            raise AccountCoordinatorError("persisted current lease digest must be a string or null")
        head = _LeaseHead(
            account_id=_required_text(row, "account_id"),
            last_fencing_generation=_required_integer(row, "last_fencing_generation"),
            current_fencing_generation=current_generation,
            current_lease_sha256=current_digest,
            updated_at=_required_datetime(row, "updated_at"),
        )
        if head.last_fencing_generation < 0:
            raise AccountCoordinatorError("persisted fencing generation cannot be negative")
        if (head.current_fencing_generation is None) != (head.current_lease_sha256 is None):
            raise AccountCoordinatorError("persisted current lease head is incomplete")
        if (
            head.current_fencing_generation is not None
            and head.current_fencing_generation != head.last_fencing_generation
        ):
            raise AccountCoordinatorError("persisted current lease generation is not latest")
        return head
    except AccountCoordinatorError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AccountCoordinatorError("persisted account lease head is malformed") from error


def verify_account_lease_history(
    *,
    account_id: str,
    head: _LeaseHead,
    leases: Sequence[AccountLease],
    releases: Sequence[AccountLeaseRelease],
    expected_policy_sha256: str | None = None,
) -> AccountLease | None:
    """Reconstruct and authenticate one account's complete coordinator history."""

    if head.account_id != account_id:
        raise AccountCoordinatorError("account lease head belongs to a different account")
    if any(type(lease) is not AccountLease or lease.account_id != account_id for lease in leases):
        raise AccountCoordinatorError("account lease history contains a foreign lease")
    if any(
        type(release) is not AccountLeaseRelease or release.fence.account_id != account_id
        for release in releases
    ):
        raise AccountCoordinatorError("account lease history contains a foreign release")
    if head.last_fencing_generation == 0:
        if leases or releases or head.current_lease_sha256 is not None:
            raise AccountCoordinatorError("empty account lease head has immutable history")
        return None
    if not leases:
        raise AccountCoordinatorError("account lease head lacks its immutable history")

    leases_by_generation: dict[int, list[AccountLease]] = {}
    for lease in leases:
        leases_by_generation.setdefault(lease.fencing_generation, []).append(lease)
    expected_generations = set(range(1, head.last_fencing_generation + 1))
    if set(leases_by_generation) != expected_generations:
        raise AccountCoordinatorError("account lease generations are not contiguous from one")

    releases_by_generation: dict[int, list[AccountLeaseRelease]] = {}
    for release in releases:
        releases_by_generation.setdefault(release.fence.fencing_generation, []).append(release)
    if not set(releases_by_generation).issubset(expected_generations):
        raise AccountCoordinatorError("account lease release has an unknown fencing generation")

    account_policy_sha256: str | None = expected_policy_sha256
    lease_ttl: timedelta | None = None
    prior_release: AccountLeaseRelease | None = None
    latest: AccountLease | None = None
    for generation in range(1, head.last_fencing_generation + 1):
        revisions = sorted(
            leases_by_generation[generation],
            key=lambda lease: (lease.heartbeat_at, lease.expires_at, lease.semantic_sha256),
        )
        first = revisions[0]
        if first.heartbeat_at != first.acquired_at:
            raise AccountCoordinatorError(
                "account lease generation lacks its canonical acquisition revision"
            )
        stable_identity = (
            first.account_id,
            first.owner_id,
            first.lease_id,
            first.fencing_generation,
            first.acquired_at,
            first.policy_sha256,
        )
        generation_ttl = first.expires_at - first.heartbeat_at
        if lease_ttl is None:
            lease_ttl = generation_ttl
        elif generation_ttl != lease_ttl:
            raise AccountCoordinatorError("account lease policy has inconsistent lease duration")
        if account_policy_sha256 is None:
            account_policy_sha256 = first.policy_sha256
        elif first.policy_sha256 != account_policy_sha256:
            raise AccountLeaseConflict(
                "durable account coordinator policy conflicts with its history"
            )
        if prior_release is not None and first.acquired_at < prior_release.released_at:
            raise AccountCoordinatorError("account lease generation predates its prior release")

        prior_revision: AccountLease | None = None
        for revision in revisions:
            if (
                revision.account_id,
                revision.owner_id,
                revision.lease_id,
                revision.fencing_generation,
                revision.acquired_at,
                revision.policy_sha256,
            ) != stable_identity:
                raise AccountCoordinatorError(
                    "account lease generation changes its stable authority identity"
                )
            if revision.expires_at - revision.heartbeat_at != generation_ttl:
                raise AccountCoordinatorError(
                    "account lease generation changes its policy lease duration"
                )
            if prior_revision is not None and (
                revision.heartbeat_at <= prior_revision.heartbeat_at
                or revision.expires_at <= prior_revision.expires_at
            ):
                raise AccountCoordinatorError(
                    "account lease renewal revisions are not strictly increasing"
                )
            prior_revision = revision
        latest = revisions[-1]

        generation_releases = releases_by_generation.get(generation, [])
        is_current_active = (
            generation == head.last_fencing_generation
            and head.current_lease_sha256 is not None
        )
        expected_release_count = 0 if is_current_active else 1
        if len(generation_releases) != expected_release_count:
            raise AccountCoordinatorError(
                "account lease generation lacks exactly one canonical terminal release"
            )
        if is_current_active:
            prior_release = None
            continue
        terminal_release = generation_releases[0]
        if (
            terminal_release.fence != latest.fence
            or terminal_release.lease_sha256 != latest.semantic_sha256
            or terminal_release.policy_sha256 != latest.policy_sha256
        ):
            raise AccountCoordinatorError(
                "account lease release does not bind the generation's final revision"
            )
        if not (latest.heartbeat_at <= terminal_release.released_at < latest.expires_at):
            raise AccountCoordinatorError("account lease release is outside its active interval")
        prior_release = terminal_release

    if latest is None:  # pragma: no cover - guarded by the non-empty contiguous history above
        raise AccountCoordinatorError("account lease history has no latest revision")
    if head.current_lease_sha256 is None:
        if prior_release is None or head.updated_at < prior_release.released_at:
            raise AccountCoordinatorError("inactive account lease head predates its release")
    else:
        if latest.semantic_sha256 != head.current_lease_sha256:
            raise AccountCoordinatorError("current account lease is not its latest revision")
        if head.updated_at < latest.heartbeat_at:
            raise AccountCoordinatorError("current account lease head predates its revision")
    return latest


class _SqlAccountCoordinatorState:
    __slots__ = ("effect_connection", "effect_in_progress", "lock")

    def __init__(self) -> None:
        self.effect_connection: Connection | None = None
        self.effect_in_progress = False
        self.lock = threading.RLock()


class SqlAccountCoordinatorAuthority:
    """Own one immutable SQL engine, timing policy, and trusted clock."""

    __slots__ = ("_clock", "_engine", "_policy", "_states", "_states_lock")

    def __init__(
        self,
        *,
        engine: Engine,
        policy: AccountLeasePolicy,
        clock: Clock,
    ) -> None:
        if not isinstance(engine, Engine):
            raise AccountCoordinatorError("SQL coordinator authority requires an engine")
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise AccountCoordinatorError(
                f"SQL coordinator does not support dialect {engine.dialect.name!r}"
            )
        if type(policy) is not AccountLeasePolicy:
            raise AccountCoordinatorError("coordinator authority requires an exact lease policy")
        if not callable(getattr(clock, "now", None)):
            raise AccountCoordinatorError("coordinator authority requires a trusted clock")
        self._engine = engine
        self._policy = policy
        self._clock = clock
        self._states: dict[str, _SqlAccountCoordinatorState] = {}
        self._states_lock = threading.Lock()

    @property
    def policy(self) -> AccountLeasePolicy:
        return self._policy

    @property
    def clock(self) -> Clock:
        return self._clock

    def _state_for(self, account_id: str) -> _SqlAccountCoordinatorState:
        with self._states_lock:
            state = self._states.get(account_id)
            if state is None:
                state = _SqlAccountCoordinatorState()
                self._states[account_id] = state
            return state


@contextmanager
def _write_transaction(engine: Engine) -> Iterator[Connection]:
    """Open a write-serializing transaction for either supported backend."""

    with engine.connect() as connection:
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()
            return
        if connection.dialect.name == "postgresql":
            with connection.begin():
                yield connection
            return
        raise AccountCoordinatorError(
            f"SQL coordinator does not support dialect {connection.dialect.name!r}"
        )


class SqlAccountCoordinator:
    """Serialize one account through durable lease heads and immutable evidence."""

    __slots__ = ("_account_id", "_authority", "_state")

    def __init__(
        self,
        *,
        account_id: str,
        authority: SqlAccountCoordinatorAuthority,
    ) -> None:
        if type(account_id) is not str or not account_id or account_id != account_id.strip():
            raise AccountCoordinatorError("coordinator account ID must be non-empty and trimmed")
        if type(authority) is not SqlAccountCoordinatorAuthority:
            raise AccountCoordinatorError("SQL coordinator requires its exact authority type")
        self._account_id = account_id
        self._authority = authority
        self._state = authority._state_for(account_id)

    @property
    def account_id(self) -> str:
        return self._account_id

    def _trusted_now(self) -> datetime:
        instant = self._authority.clock.now()
        if not isinstance(instant, datetime):
            raise AccountCoordinatorError("coordinator clock returned a non-datetime value")
        try:
            require_utc(instant, "coordinator clock instant")
        except ValueError as error:
            raise AccountCoordinatorError(str(error)) from error
        return instant.astimezone(UTC)

    def _head_statement(self, *, lock: bool) -> sa.Select[tuple[Any, ...]]:
        statement = sa.select(phase2_account_lease_heads).where(
            phase2_account_lease_heads.c.account_id == self.account_id
        )
        if lock and self._authority._engine.dialect.name == "postgresql":
            statement = statement.with_for_update()
        return statement

    def _head(self, connection: Connection, *, lock: bool) -> _LeaseHead | None:
        if lock and connection.dialect.name == "sqlite":
            connection.execute(
                sa.update(phase2_account_lease_heads)
                .where(phase2_account_lease_heads.c.account_id == self.account_id)
                .values(updated_at=phase2_account_lease_heads.c.updated_at)
            )
        row = connection.execute(self._head_statement(lock=lock)).mappings().one_or_none()
        return None if row is None else _lease_head_from_row(row)

    def _bootstrap_head(self, connection: Connection, observed_at: datetime) -> _LeaseHead:
        values = {
            "account_id": self.account_id,
            "last_fencing_generation": 0,
            "current_fencing_generation": None,
            "current_lease_sha256": None,
            "updated_at": observed_at,
        }
        if connection.dialect.name == "postgresql":
            statement = (
                postgresql_insert(phase2_account_lease_heads)
                .values(**values)
                .on_conflict_do_nothing()
            )
            connection.execute(statement)
        elif connection.dialect.name == "sqlite":
            sqlite_statement = (
                sqlite_insert(phase2_account_lease_heads).values(**values).on_conflict_do_nothing()
            )
            connection.execute(sqlite_statement)
        else:
            raise AccountCoordinatorError(
                f"SQL coordinator does not support dialect {connection.dialect.name!r}"
            )
        head = self._head(connection, lock=True)
        if head is None:
            raise AccountCoordinatorError("account lease head bootstrap was not durable")
        return head

    @staticmethod
    def _lease_by_digest(connection: Connection, lease_sha256: str) -> AccountLease | None:
        row = (
            connection.execute(
                sa.select(phase2_account_leases).where(
                    phase2_account_leases.c.lease_sha256 == lease_sha256
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else account_lease_from_row(row)

    def _latest_lease(self, connection: Connection) -> AccountLease | None:
        row = (
            connection.execute(
                sa.select(phase2_account_leases)
                .where(phase2_account_leases.c.account_id == self.account_id)
                .order_by(
                    phase2_account_leases.c.fencing_generation.desc(),
                    phase2_account_leases.c.heartbeat_at.desc(),
                )
                .limit(1)
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else account_lease_from_row(row)

    def _verify_history(
        self,
        connection: Connection,
        head: _LeaseHead,
    ) -> AccountLease | None:
        leases = tuple(
            account_lease_from_row(row)
            for row in connection.execute(
                sa.select(phase2_account_leases).where(
                    phase2_account_leases.c.account_id == self.account_id
                )
            ).mappings()
        )
        releases = tuple(
            account_lease_release_from_row(row)
            for row in connection.execute(
                sa.select(phase2_account_lease_releases).where(
                    phase2_account_lease_releases.c.account_id == self.account_id
                )
            ).mappings()
        )
        return verify_account_lease_history(
            account_id=self.account_id,
            head=head,
            leases=leases,
            releases=releases,
            expected_policy_sha256=self._authority.policy.semantic_sha256,
        )

    def _current_from_head(
        self,
        connection: Connection,
        head: _LeaseHead,
    ) -> AccountLease | None:
        self._verify_history(connection, head)
        if head.current_lease_sha256 is None:
            return None
        current = self._lease_by_digest(connection, head.current_lease_sha256)
        if current is None:
            raise AccountCoordinatorError("account lease head references a missing lease")
        if (
            current.account_id != self.account_id
            or current.fencing_generation != head.current_fencing_generation
            or current.policy_sha256 != self._authority.policy.semantic_sha256
        ):
            raise AccountCoordinatorError("account lease head conflicts with its current lease")
        return current

    def _observe(
        self,
        connection: Connection,
        head: _LeaseHead,
        checked_at: datetime,
    ) -> _LeaseHead:
        if checked_at < head.updated_at:
            raise AccountCoordinatorError("coordinator clock cannot regress")
        updated = connection.execute(
            sa.update(phase2_account_lease_heads)
            .where(
                phase2_account_lease_heads.c.account_id == self.account_id,
                phase2_account_lease_heads.c.last_fencing_generation
                == head.last_fencing_generation,
                phase2_account_lease_heads.c.current_lease_sha256.is_(head.current_lease_sha256)
                if head.current_lease_sha256 is None
                else phase2_account_lease_heads.c.current_lease_sha256 == head.current_lease_sha256,
            )
            .values(updated_at=checked_at)
        )
        if updated.rowcount != 1:
            raise AccountLeaseConflict("account lease head changed concurrently")
        persisted = self._head(connection, lock=False)
        if persisted is None or persisted.updated_at != checked_at:
            raise AccountCoordinatorError("coordinator clock observation was not durable")
        return persisted

    @staticmethod
    def _require_exact_fence(fence: AccountFence, current: AccountLease | None) -> AccountLease:
        if type(fence) is not AccountFence:
            raise AccountLeaseOwnershipLost("coordinator requires an exact AccountFence")
        if current is None or fence != current.fence:
            raise AccountLeaseOwnershipLost("account fence is no longer current")
        return current

    def _receipt(
        self,
        fence: AccountFence,
        current: AccountLease | None,
        checked_at: datetime,
    ) -> AccountFenceReceipt:
        lease = self._require_exact_fence(fence, current)
        if checked_at >= lease.expires_at:
            raise AccountLeaseOwnershipLost("account coordinator lease has expired")
        return _account_fence_receipt(
            fence=fence,
            validated_at=checked_at,
            valid_until=lease.expires_at,
            policy_sha256=self._authority.policy.semantic_sha256,
            lease_sha256=lease.semantic_sha256,
        )

    def _insert_lease(self, connection: Connection, lease: AccountLease) -> AccountLease:
        values = immutable_account_lease_values(lease)
        try:
            connection.execute(sa.insert(phase2_account_leases).values(**values))
        except IntegrityError as error:
            raise AccountLeaseConflict(
                "account lease revision conflicts with durable history"
            ) from error
        persisted = self._lease_by_digest(connection, lease.semantic_sha256)
        if persisted != lease:
            raise AccountCoordinatorError("account lease revision failed exact SQL readback")
        return persisted

    def _set_head(
        self,
        connection: Connection,
        prior: _LeaseHead,
        *,
        last_generation: int,
        current_lease: AccountLease | None,
        updated_at: datetime,
    ) -> _LeaseHead:
        updated = connection.execute(
            sa.update(phase2_account_lease_heads)
            .where(
                phase2_account_lease_heads.c.account_id == self.account_id,
                phase2_account_lease_heads.c.last_fencing_generation
                == prior.last_fencing_generation,
                phase2_account_lease_heads.c.current_lease_sha256.is_(prior.current_lease_sha256)
                if prior.current_lease_sha256 is None
                else phase2_account_lease_heads.c.current_lease_sha256
                == prior.current_lease_sha256,
            )
            .values(
                last_fencing_generation=last_generation,
                current_fencing_generation=(
                    None if current_lease is None else current_lease.fencing_generation
                ),
                current_lease_sha256=(
                    None if current_lease is None else current_lease.semantic_sha256
                ),
                updated_at=updated_at,
            )
        )
        if updated.rowcount != 1:
            raise AccountLeaseConflict("account lease head changed concurrently")
        persisted = self._head(connection, lock=False)
        if persisted is None:
            raise AccountCoordinatorError("account lease head update was not durable")
        expected = _LeaseHead(
            account_id=self.account_id,
            last_fencing_generation=last_generation,
            current_fencing_generation=(
                None if current_lease is None else current_lease.fencing_generation
            ),
            current_lease_sha256=(None if current_lease is None else current_lease.semantic_sha256),
            updated_at=updated_at,
        )
        if persisted != expected:
            raise AccountCoordinatorError("account lease head failed exact SQL readback")
        return persisted

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
            rejection: AccountCoordinatorError | None = None
            acquired: AccountLease | None = None
            with _write_transaction(self._authority._engine) as connection:
                head = self._bootstrap_head(connection, now)
                current = self._current_from_head(connection, head)
                observed_head = self._observe(connection, head, now)
                if current is not None:
                    if now >= current.expires_at:
                        rejection = AccountLeaseOwnershipLost(
                            "expired coordinator ownership requires durable reconciliation takeover"
                        )
                    elif current.owner_id == owner_id:
                        acquired = current
                    else:
                        rejection = AccountLeaseConflict(
                            "account already has an active coordinator owner"
                        )
                else:
                    generation = observed_head.last_fencing_generation + 1
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
                        acquired_at=now,
                        heartbeat_at=now,
                        expires_at=now + self._authority.policy.lease_ttl,
                        policy_sha256=self._authority.policy.semantic_sha256,
                    )
                    acquired = self._insert_lease(connection, lease)
                    self._set_head(
                        connection,
                        observed_head,
                        last_generation=generation,
                        current_lease=acquired,
                        updated_at=now,
                    )
            if rejection is not None:
                raise rejection
            if acquired is None:
                raise AccountCoordinatorError("account acquisition produced no lease")
            return acquired

    def current(self) -> AccountLease | None:
        with self._state.lock:
            connection = self._state.effect_connection
            if connection is not None:
                head = self._head(connection, lock=False)
                return None if head is None else self._current_from_head(connection, head)
            with self._authority._engine.connect() as read_connection:
                head = self._head(read_connection, lock=False)
                if head is None:
                    if self._latest_lease(read_connection) is not None:
                        raise AccountCoordinatorError(
                            "account lease history exists without its durable head"
                        )
                    return None
                return self._current_from_head(read_connection, head)

    def renew(self, fence: AccountFence) -> AccountLease:
        if type(fence) is not AccountFence:
            raise AccountLeaseOwnershipLost("coordinator requires an exact AccountFence")
        with self._state.lock:
            self._require_no_effect_transition()
            rejection: AccountCoordinatorError | None = None
            renewed: AccountLease | None = None
            with _write_transaction(self._authority._engine) as connection:
                head = self._head(connection, lock=True)
                if head is None:
                    raise AccountLeaseOwnershipLost("account fence is no longer current")
                current = self._require_exact_fence(
                    fence,
                    self._current_from_head(connection, head),
                )
                now = self._trusted_now()
                observed_head = self._observe(connection, head, now)
                if now >= current.expires_at:
                    rejection = AccountLeaseOwnershipLost(
                        "expired coordinator lease cannot be renewed"
                    )
                elif now == current.heartbeat_at:
                    renewed = current
                else:
                    expires_at = now + self._authority.policy.lease_ttl
                    if expires_at <= current.expires_at:
                        rejection = AccountCoordinatorError(
                            "lease renewal must extend the current expiry"
                        )
                    else:
                        lease_revision = AccountLease(
                            account_id=current.account_id,
                            owner_id=current.owner_id,
                            lease_id=current.lease_id,
                            fencing_generation=current.fencing_generation,
                            acquired_at=current.acquired_at,
                            heartbeat_at=now,
                            expires_at=expires_at,
                            policy_sha256=current.policy_sha256,
                        )
                        renewed = self._insert_lease(connection, lease_revision)
                        self._set_head(
                            connection,
                            observed_head,
                            last_generation=current.fencing_generation,
                            current_lease=renewed,
                            updated_at=now,
                        )
            if rejection is not None:
                raise rejection
            if renewed is None:
                raise AccountCoordinatorError("lease renewal produced no revision")
            return renewed

    def revalidate_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
        *,
        checked_at: datetime,
    ) -> AccountFenceReceipt:
        """Lock and validate a fence inside a caller-owned SQL transaction.

        ``checked_at`` is the logical event time bound into the returned
        receipt.  It is not an authority clock: the coordinator samples its
        trusted clock again while holding the durable lease head so callers
        cannot backdate a mutation past real lease expiry or control the
        durable observation head.
        """

        if not isinstance(connection, Connection) or not connection.in_transaction():
            raise AccountCoordinatorError(
                "transactional fence validation requires an active SQLAlchemy transaction"
            )
        if connection.engine is not self._authority._engine:
            raise AccountCoordinatorError(
                "transactional fence validation requires the coordinator authority engine"
            )
        if type(fence) is not AccountFence:
            raise AccountLeaseOwnershipLost("coordinator requires an exact AccountFence")
        if not isinstance(checked_at, datetime):
            raise AccountCoordinatorError("fence checked_at must be a datetime")
        try:
            require_utc(checked_at, "fence checked_at")
        except ValueError as error:
            raise AccountCoordinatorError(str(error)) from error
        checked_at = checked_at.astimezone(UTC)
        head = self._head(connection, lock=True)
        if head is None:
            raise AccountLeaseOwnershipLost("account fence is no longer current")
        trusted_now = self._trusted_now()
        if trusted_now < head.updated_at:
            raise AccountCoordinatorError("coordinator clock cannot regress")
        if checked_at < head.updated_at:
            raise AccountCoordinatorError("fence checked_at cannot regress")
        current = self._current_from_head(connection, head)
        if current is not None and trusted_now < current.heartbeat_at:
            raise AccountCoordinatorError("coordinator clock cannot predate the lease revision")
        if current is not None and checked_at < current.heartbeat_at:
            raise AccountCoordinatorError("fence checked_at cannot predate the lease revision")
        # This receipt is deliberately not returned: it is the transaction-time
        # authority guard.  In particular, it rejects an expired lease even if
        # a caller supplies an earlier logical event time.
        self._receipt(fence, current, trusted_now)
        self._observe(connection, head, trusted_now)
        return self._receipt(fence, current, checked_at)

    def revalidate(self, fence: AccountFence) -> AccountFenceReceipt:
        with self._state.lock:
            now = self._trusted_now()
            connection = self._state.effect_connection
            if connection is not None:
                return self.revalidate_in_transaction(
                    connection,
                    fence,
                    checked_at=now,
                )
            rejection: AccountCoordinatorError | None = None
            receipt: AccountFenceReceipt | None = None
            with _write_transaction(self._authority._engine) as write_connection:
                try:
                    receipt = self.revalidate_in_transaction(
                        write_connection,
                        fence,
                        checked_at=now,
                    )
                except AccountCoordinatorError as error:
                    rejection = error
            if rejection is not None:
                raise rejection
            if receipt is None:
                raise AccountCoordinatorError("fence validation produced no receipt")
            return receipt

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
            callback_error: BaseException | None = None
            callback_traceback: TracebackType | None = None
            validation_error: AccountCoordinatorError | None = None
            result: FencedResultT | None = None
            with _write_transaction(self._authority._engine) as connection:
                try:
                    receipt = self.revalidate_in_transaction(
                        connection,
                        fence,
                        checked_at=now,
                    )
                except AccountCoordinatorError as error:
                    validation_error = error
                else:
                    self._state.effect_in_progress = True
                    self._state.effect_connection = connection
                    try:
                        result = operation(receipt)
                    except BaseException as error:
                        callback_error = error
                        callback_traceback = error.__traceback__
                    finally:
                        self._state.effect_connection = None
                        self._state.effect_in_progress = False
            if validation_error is not None:
                raise validation_error
            if callback_error is not None:
                raise callback_error.with_traceback(callback_traceback)
            return cast(FencedResultT, result)

    def _release_for_fence(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountLeaseRelease | None:
        rows = (
            connection.execute(
                sa.select(phase2_account_lease_releases).where(
                    phase2_account_lease_releases.c.account_id == fence.account_id,
                    phase2_account_lease_releases.c.owner_id == fence.owner_id,
                    phase2_account_lease_releases.c.lease_id == fence.lease_id,
                    phase2_account_lease_releases.c.fencing_generation == fence.fencing_generation,
                )
            )
            .mappings()
            .all()
        )
        if not rows:
            return None
        if len(rows) != 1:
            raise AccountCoordinatorError("account fence has multiple durable releases")
        release = account_lease_release_from_row(rows[0])
        lease = self._lease_by_digest(connection, release.lease_sha256)
        if (
            release.fence != fence
            or release.policy_sha256 != self._authority.policy.semantic_sha256
            or lease is None
            or lease.fence != release.fence
            or lease.policy_sha256 != release.policy_sha256
        ):
            raise AccountCoordinatorError("account lease release conflicts with its lease")
        return release

    def release(self, fence: AccountFence) -> AccountLeaseRelease:
        if type(fence) is not AccountFence:
            raise AccountLeaseOwnershipLost("coordinator requires an exact AccountFence")
        with self._state.lock:
            self._require_no_effect_transition()
            rejection: AccountLeaseOwnershipLost | None = None
            released: AccountLeaseRelease | None = None
            with _write_transaction(self._authority._engine) as connection:
                prior_release = self._release_for_fence(connection, fence)
                if prior_release is not None:
                    return prior_release
                head = self._head(connection, lock=True)
                if head is None:
                    raise AccountLeaseOwnershipLost("account fence is no longer current")
                # A release that raced another process may become visible only
                # after this transaction obtained the durable head lock.
                prior_release = self._release_for_fence(connection, fence)
                if prior_release is not None:
                    return prior_release
                now = self._trusted_now()
                current = self._require_exact_fence(
                    fence,
                    self._current_from_head(connection, head),
                )
                observed_head = self._observe(connection, head, now)
                try:
                    self._receipt(fence, current, now)
                except AccountLeaseOwnershipLost as error:
                    rejection = error
                else:
                    release = _account_lease_release(
                        fence=fence,
                        released_at=now,
                        policy_sha256=self._authority.policy.semantic_sha256,
                        lease_sha256=current.semantic_sha256,
                    )
                    values = immutable_account_lease_release_values(release)
                    try:
                        connection.execute(
                            sa.insert(phase2_account_lease_releases).values(**values)
                        )
                    except IntegrityError as error:
                        raise AccountLeaseConflict(
                            "account lease release conflicts with durable history"
                        ) from error
                    released = self._release_for_fence(connection, fence)
                    if released != release:
                        raise AccountCoordinatorError(
                            "account lease release failed exact SQL readback"
                        )
                    self._set_head(
                        connection,
                        observed_head,
                        last_generation=current.fencing_generation,
                        current_lease=None,
                        updated_at=now,
                    )
            if rejection is not None:
                raise rejection
            if released is None:
                raise AccountCoordinatorError("lease release produced no durable fact")
            return released
