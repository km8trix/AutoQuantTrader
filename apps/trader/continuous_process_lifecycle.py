"""Read-only parent ownership observation for the fixed offline worker.

Private handshake records are bounded lifecycle data, never C/B/A receipt
ownership, readiness, delivery permission, or a replacement for child integrity.
"""

from __future__ import annotations

import json
import math
import os
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, NoReturn, cast
from urllib.parse import unquote, urlparse

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.pool import NullPool

from packages.application.continuous_process import (
    ContinuousLifecyclePhase,
    ContinuousProcessRequest,
    ContinuousProcessStartup,
    ContinuousWorkerContext,
    _encode,
    _private_directory,
    _private_read,
    _private_write,
)
from packages.domain.account_coordinator import AccountLease, AccountLeaseRelease
from packages.domain.continuous_persistence_contracts import ContinuousAccountScope
from packages.domain.personal_contracts import content_digest
from packages.persistence.account_coordinator import (
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.database import EXPECTED_SCHEMA_REVISION, _continuous_field_check
from packages.persistence.immutable import as_aware_utc
from packages.persistence.schema import (
    phase2_account_lease_heads as heads,
)
from packages.persistence.schema import (
    phase2_account_lease_releases as releases,
)
from packages.persistence.schema import (
    phase2_account_leases as leases,
)
from packages.persistence.schema import (
    phase5_operational_control_heads as controls,
)
from packages.persistence.schema import (
    phase5_operational_control_transitions as transitions,
)

if TYPE_CHECKING:
    from apps.trader.continuous_simulation_factory import ContinuousSimulationConfiguration

_MAX_FRAME = 4096
_MAX_PROBE_BYTES = 256 * 1024


class ContinuousLifecycleError(ValueError):
    """Static failure; no private paths or retained payloads are exposed."""


def _fail() -> NoReturn:
    raise ContinuousLifecycleError("ORIGINAL_CONTINUOUS_LIFECYCLE_REQUIRED")


def _bytes(value: dict[str, Any]) -> bytes:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if not 0 < len(payload) <= _MAX_FRAME:
        _fail()
    return payload


def _read(path: Path) -> dict[str, Any]:
    payload = _private_read(path, _MAX_FRAME)
    value = json.loads(payload)
    if type(value) is not dict or _bytes(value) != payload:
        _fail()
    return cast(dict[str, Any], value)


def _optional_read(path: Path) -> dict[str, Any] | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return _read(path)


def _publish(path: Path, value: dict[str, Any]) -> None:
    """Publish one complete frame; partial bytes are never a visible handshake."""
    pending = path.with_name(path.name + ".pending")
    try:
        _private_write(pending, _bytes(value))
        if path.exists() or path.is_symlink():
            _fail()
        pending.rename(path)
    finally:
        pending.unlink(missing_ok=True)


def _identity(path: Path) -> tuple[int, int]:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
        or not 0 < info.st_size <= 256 * 1024 * 1024
    ):
        _fail()
    return info.st_dev, info.st_ino


def _digest(value: object) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        _fail()


def _nonce(value: object) -> None:
    if (
        type(value) is not str
        or len(value) != 32
        or any(c not in "0123456789abcdef" for c in value)
    ):
        _fail()


def _lease_fields(lease: AccountLease) -> dict[str, Any]:
    return {
        "account_id": lease.account_id,
        "owner_id": lease.owner_id,
        "lease_id": lease.lease_id,
        "generation": lease.fencing_generation,
        "lease_sha256": lease.semantic_sha256,
        "policy_sha256": lease.policy_sha256,
        "acquired_at": lease.acquired_at.isoformat(),
        "expires_at": lease.expires_at.isoformat(),
    }


@dataclass(frozen=True, slots=True)
class _Rows:
    head: Any
    lease: Any
    release: Any
    control: Any
    transition: Any


class _ReadOnlyDatabase:
    def __init__(self, path: Path, account_id: str) -> None:
        self.path, self.account_id = path, account_id
        self.identity = _identity(path)
        url = sa.URL.create(
            "sqlite+pysqlite", database=path.as_uri(), query={"mode": "ro", "uri": "true"}
        )
        # Do not use the ordinary engine factory: its WAL setup is a write.
        self.engine = sa.create_engine(url, poolclass=NullPool, connect_args={"timeout": 0.1})

    def capture(self) -> _Rows:
        if _identity(self.path) != self.identity:
            _fail()
        with self.engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA query_only=ON")
            connection.exec_driver_sql("BEGIN")
            used = 0

            def one(table: sa.Table, *predicates: Any, order: Any = None) -> Any:
                nonlocal used
                checks = tuple(_continuous_field_check(connection, column) for column in table.c)
                invalid = sa.or_(*(sa.not_(valid) for valid, _ in checks))
                lengths = sum((length for _, length in checks), sa.literal(0))
                statement = (
                    sa.select(
                        sa.case((invalid, 1), else_=0).label("invalid"), lengths.label("bytes")
                    )
                    .where(*predicates)
                    .limit(2)
                )
                if order is not None:
                    statement = statement.order_by(order).limit(1)
                sizes = tuple(connection.execute(statement))
                if len(sizes) > 1 or any(row.invalid for row in sizes):
                    _fail()
                used += sum(int(row.bytes) for row in sizes)
                if used > _MAX_PROBE_BYTES:
                    _fail()
                selected = sa.select(table).where(*predicates).limit(2)
                if order is not None:
                    selected = selected.order_by(order).limit(1)
                rows = tuple(connection.execute(selected).mappings())
                if len(rows) != len(sizes):
                    _fail()
                return None if not rows else MappingProxyType(dict(rows[0]))

            try:
                versions = tuple(
                    connection.scalars(
                        sa.text(
                            "SELECT CASE WHEN typeof(version_num) = 'text' "
                            "AND version_num = :expected THEN 1 ELSE 0 END "
                            "FROM alembic_version LIMIT 2"
                        ),
                        {"expected": EXPECTED_SCHEMA_REVISION},
                    )
                )
                if versions != (1,):
                    _fail()
                head = one(heads, heads.c.account_id == self.account_id)
                control = one(controls, controls.c.account_id == self.account_id)
                if head is None or control is None:
                    _fail()
                lease = one(
                    leases,
                    leases.c.account_id == self.account_id,
                    leases.c.fencing_generation == head["last_fencing_generation"],
                    order=leases.c.revision_number.desc(),
                )
                release = one(
                    releases,
                    releases.c.account_id == self.account_id,
                    releases.c.fencing_generation == head["last_fencing_generation"],
                )
                transition = one(
                    transitions, transitions.c.transition_id == control["transition_id"]
                )
                return _Rows(head, lease, release, control, transition)
            finally:
                connection.rollback()


def _halted(rows: _Rows) -> None:
    if (
        rows.control["effective_state"] != "halted"
        or rows.transition is None
        or rows.transition["account_id"] != rows.head["account_id"]
        or rows.transition["sequence_number"] != rows.control["sequence_number"]
        or rows.transition["transition_id"] != rows.control["transition_id"]
        or rows.transition["semantic_sha256"] != rows.control["transition_sha256"]
    ):
        _fail()


class SqlContinuousParentProbe:
    """Observe exact configured rows without any coordinator or mutation method."""

    def __init__(self, request: ContinuousProcessRequest) -> None:
        if type(request) is not ContinuousProcessRequest:
            _fail()
        request.__post_init__()
        self.request = request
        self._startup: ContinuousProcessStartup | None = None
        self._database: _ReadOnlyDatabase | None = None
        self._initial: _Rows | None = None
        self._ready: dict[str, Any] | None = None
        self._released: dict[str, Any] | None = None
        self._closing: dict[str, Any] | None = None
        self._closing_deadline: float | None = None
        self._observed_exit = False
        self._original_lease: Any = None
        self._last_utc: datetime | None = None
        self._last_head_at: datetime | None = None
        self._pid: int | None = None
        self._phase: ContinuousLifecyclePhase = "starting"

    def prepare(self, startup: ContinuousProcessStartup) -> None:
        from apps.trader.continuous_simulation_factory import load_continuous_configuration

        if (
            type(startup) is not ContinuousProcessStartup
            or self._startup is not None
            or startup.request is not self.request
            or startup.request_sha256 != sha256(_encode(self.request)).hexdigest()
            or startup.configuration_sha256
            != sha256(_private_read(self.request.configuration_path, 64 * 1024)).hexdigest()
        ):
            _fail()
        _private_directory(startup.directory)
        _nonce(startup.parent_nonce)
        config = load_continuous_configuration(self.request.configuration_path)
        self._configuration = config
        self._startup = startup
        self._database = _ReadOnlyDatabase(Path(config.database_path), self.request.account_id)
        rows = self._database.capture()
        _halted(rows)
        if rows.head["current_lease_sha256"] is not None:
            _fail()
        self._initial = rows
        self._envelope = {
            "schema": "continuous-lifecycle/1",
            "account_id": self.request.account_id,
            "operation_id": self.request.operation_id,
            "parent_nonce": startup.parent_nonce,
            "parent_pid": startup.parent_pid,
            "request_sha256": startup.request_sha256,
            "configuration_sha256": startup.configuration_sha256,
            "lock_identity": [startup.lock_device, startup.lock_inode],
            "database_identity": list(self._database.identity),
            "startup_deadline": startup.startup_deadline,
        }
        _publish(startup.directory / "lifecycle.json", self._envelope)

    def observe(self, *, child_pid: int | None, child_exited: bool) -> ContinuousLifecyclePhase:
        startup, database, initial = self._startup, self._database, self._initial
        if startup is None or database is None or initial is None:
            _fail()
        assert startup is not None and database is not None and initial is not None
        if child_pid is not None:
            if type(child_pid) is not int or child_pid <= 1 or self._pid not in (None, child_pid):
                _fail()
            self._pid = child_pid
        elif self._pid is not None or child_exited:
            _fail()
        if (
            self.request is not startup.request
            or sha256(_encode(self.request)).hexdigest() != startup.request_sha256
            or database.path != Path(self._configuration.database_path)
            or list(database.identity) != self._envelope["database_identity"]
            or _read(startup.directory / "lifecycle.json") != self._envelope
            or sha256(_private_read(self.request.configuration_path, 64 * 1024)).hexdigest()
            != startup.configuration_sha256
        ):
            _fail()
        # Capture immutable child frames before SQL. A newly acquired/released
        # lease may then appear before its frame, but a new frame can never be
        # paired with an older SQL snapshot from the same observation.
        ready_frame = _optional_read(startup.directory / "lease-ready.json")
        closing_frame = _optional_read(startup.directory / "result-ready.json")
        released_frame = _optional_read(startup.directory / "lease-released.json")
        rows = database.capture()
        if rows.release is not None and self._ready is not None and closing_frame is None:
            # Successful work may publish result-ready and commit release during
            # the first SQL read. Take one bounded complete follow-up; an early
            # release still fails unless its original result-ready exists.
            ready_frame = _optional_read(startup.directory / "lease-ready.json")
            closing_frame = _optional_read(startup.directory / "result-ready.json")
            released_frame = _optional_read(startup.directory / "lease-released.json")
            rows = database.capture()
        _halted(rows)
        now = datetime.now(UTC)
        if (
            rows.control != initial.control
            or rows.transition != initial.transition
            or (self._last_utc is not None and now < self._last_utc)
        ):
            _fail()
        self._last_utc = now
        if self._ready is None:
            if time.monotonic() >= startup.startup_deadline or child_exited:
                _fail()
            if ready_frame is None:
                if rows.head["last_fencing_generation"] not in (
                    initial.head["last_fencing_generation"],
                    initial.head["last_fencing_generation"] + 1,
                ):
                    _fail()
                return "starting"
            ready = ready_frame
            if (
                set(ready)
                != {
                    "schema",
                    "envelope_sha256",
                    "child_pid",
                    "instance_nonce",
                    "scope_sha256",
                    "lease",
                    "control_sha256",
                }
                or ready["schema"] != "continuous-lease-ready/1"
                or ready["envelope_sha256"] != sha256(_bytes(self._envelope)).hexdigest()
                or child_pid is None
                or ready["child_pid"] != child_pid
                or ready["control_sha256"] != rows.control["semantic_sha256"]
            ):
                _fail()
            _nonce(ready["instance_nonce"])
            _digest(ready["scope_sha256"])
            if rows.lease is None:
                _fail()
            lease = account_lease_from_row(rows.lease)
            if (
                lease.owner_id
                != "offline-owner-"
                + content_digest((self._configuration.owner_id, child_pid, ready["instance_nonce"]))
                or _lease_fields(lease) != ready["lease"]
                or lease.fencing_generation != initial.head["last_fencing_generation"] + 1
                or lease.revision_number != 1
                or lease.policy_sha256 != self._configuration.lease_policy().semantic_sha256
            ):
                _fail()
            self._ready, self._original_lease = ready, rows.lease
        elif ready_frame != self._ready:
            _fail()
        if rows.lease != self._original_lease:
            _fail()
        lease = account_lease_from_row(rows.lease)
        at = as_aware_utc(rows.head["updated_at"])
        if self._last_head_at is not None and at < self._last_head_at:
            _fail()
        self._last_head_at = at
        if (
            rows.head["last_fencing_generation"] != lease.fencing_generation
            or at > now
            or not lease.acquired_at <= at < lease.expires_at
        ):
            _fail()
        if closing_frame is not None or self._closing is not None:
            closing = closing_frame
            if (
                closing is None
                or self._phase == "starting"
                or set(closing) != {"schema", "ready_sha256", "result_sha256", "result_bytes"}
                or closing["schema"] != "continuous-result-ready/1"
                or closing["ready_sha256"] != sha256(_bytes(self._ready)).hexdigest()
                or type(closing["result_bytes"]) is not int
                or not 0 < closing["result_bytes"] <= self.request.limits.receipt_bytes
                or self._closing not in (None, closing)
            ):
                _fail()
            _digest(closing["result_sha256"])
            if self._closing is None:
                self._closing = closing
                self._closing_deadline = min(startup.work_deadline, time.monotonic() + 1.0)
            if self._phase != "released":
                if self._closing_deadline is None or time.monotonic() >= self._closing_deadline:
                    _fail()
                self._phase = "closing"
        if rows.release is not None or released_frame is not None or self._phase == "released":
            if self._closing is None or self._phase == "starting":
                _fail()
            if rows.release is not None and released_frame is None and not child_exited:
                # Actual release can precede the terminal sidecar by a bounded
                # filesystem write. CLOSING is never a current-fence claim.
                release = account_lease_release_from_row(rows.release)
                if (
                    release.fence != lease.fence
                    or release.lease_sha256 != lease.semantic_sha256
                    or rows.head["current_lease_sha256"] is not None
                    or rows.head["current_fencing_generation"] is not None
                    or at != release.released_at
                ):
                    _fail()
                return "closing"
            if rows.release is None or released_frame is None:
                _fail()
            release = account_lease_release_from_row(rows.release)
            terminal = released_frame
            if (
                set(terminal)
                != {
                    "schema",
                    "ready_sha256",
                    "release_id",
                    "release_sha256",
                    "released_at",
                    "result_sha256",
                    "result_bytes",
                }
                or terminal["schema"] != "continuous-lease-released/1"
                or terminal["ready_sha256"] != sha256(_bytes(self._ready)).hexdigest()
                or terminal["release_id"] != release.release_id
                or terminal["release_sha256"] != release.semantic_sha256
                or terminal["released_at"] != release.released_at.isoformat()
                or release.fence != lease.fence
                or release.lease_sha256 != lease.semantic_sha256
                or release.policy_sha256 != lease.policy_sha256
                or rows.head["current_lease_sha256"] is not None
                or rows.head["current_fencing_generation"] is not None
                or at != release.released_at
                or type(terminal["result_bytes"]) is not int
                or not 0 < terminal["result_bytes"] <= self.request.limits.receipt_bytes
                or terminal["result_sha256"] != self._closing["result_sha256"]
                or terminal["result_bytes"] != self._closing["result_bytes"]
                or self._released not in (None, terminal)
            ):
                _fail()
            _digest(terminal["result_sha256"])
            self._released, self._phase = terminal, "released"
            self._observed_exit = self._observed_exit or child_exited
            return "released"
        if (
            child_exited
            or rows.head["current_lease_sha256"] != lease.semantic_sha256
            or rows.head["current_fencing_generation"] != lease.fencing_generation
            or not lease.acquired_at <= now < lease.expires_at
        ):
            _fail()
        accepted = {
            "schema": "continuous-parent-accepted/1",
            "ready_sha256": sha256(_bytes(self._ready)).hexdigest(),
        }
        accepted_path = startup.directory / "parent-accepted.json"
        if self._phase == "starting":
            _publish(accepted_path, accepted)
        elif _read(accepted_path) != accepted:
            _fail()
        if self._closing is not None:
            return "closing"
        self._phase = "leased"
        return "leased"

    def require_result(self, payload: bytes) -> None:
        if (
            self._phase != "released"
            or self._released is None
            or not self._observed_exit
            or type(payload) is not bytes
            or sha256(payload).hexdigest() != self._released["result_sha256"]
            or len(payload) != self._released["result_bytes"]
        ):
            _fail()
        value = json.loads(payload)
        if (
            type(value) is not dict
            or value.get("schema") != "continuous-offline-result/1"
            or value.get("account_id") != self.request.account_id
            or value.get("operation_id") != self.request.operation_id
            or value.get("operation") != self._configuration.operation
            or value.get("status")
            != ("restored" if self._configuration.operation == "restore" else "integrity_verified")
        ):
            _fail()


class ContinuousWorkerLifecycle:
    def __init__(self, worker: ContinuousWorkerContext) -> None:
        if type(worker) is not ContinuousWorkerContext:
            _fail()
        self.worker = worker
        self._ready: dict[str, Any] | None = None
        self._lease: AccountLease | None = None
        self._completed = False
        self._result: dict[str, Any] | None = None
        frame = _read(worker.process_directory / "lifecycle.json")
        if (
            set(frame)
            != {
                "schema",
                "account_id",
                "operation_id",
                "parent_nonce",
                "parent_pid",
                "request_sha256",
                "configuration_sha256",
                "lock_identity",
                "database_identity",
                "startup_deadline",
            }
            or frame["schema"] != "continuous-lifecycle/1"
            or frame["parent_pid"] != worker.parent_pid
            or frame["account_id"] != worker.request.account_id
            or frame["operation_id"] != worker.request.operation_id
            or frame["request_sha256"] != sha256(_encode(worker.request)).hexdigest()
            or frame["configuration_sha256"]
            != sha256(_private_read(worker.request.configuration_path, 64 * 1024)).hexdigest()
            or frame["lock_identity"] != list(worker.instance_lock_identity)
            or type(frame["startup_deadline"]) not in (float, int)
            or not math.isfinite(frame["startup_deadline"])
            or not time.monotonic() < frame["startup_deadline"] <= worker.work_deadline_monotonic
        ):
            _fail()
        _nonce(frame["parent_nonce"])
        self._frame = frame

    def acquired(
        self,
        *,
        configuration: ContinuousSimulationConfiguration,
        scope: ContinuousAccountScope,
        lease: AccountLease,
        instance_nonce: str,
        engine: Engine,
    ) -> None:
        from apps.trader.continuous_simulation_factory import ContinuousSimulationConfiguration

        if (
            type(configuration) is not ContinuousSimulationConfiguration
            or type(scope) is not ContinuousAccountScope
            or type(lease) is not AccountLease
            or self._ready is not None
            or self.worker.stop_requested()
            or scope.account_id != self.worker.request.account_id
            or lease.account_id != scope.account_id
            or engine.dialect.name != "sqlite"
            or engine.url.database is None
            or Path(unquote(urlparse(engine.url.database).path))
            != Path(configuration.database_path)
        ):
            _fail()
        _nonce(instance_nonce)
        if lease.owner_id != "offline-owner-" + content_digest(
            (configuration.owner_id, os.getpid(), instance_nonce)
        ):
            _fail()
        database = _ReadOnlyDatabase(Path(configuration.database_path), scope.account_id)
        rows = database.capture()
        _halted(rows)
        if (
            database.identity != tuple(self._frame["database_identity"])
            or account_lease_from_row(rows.lease) != lease
        ):
            _fail()
        ready = {
            "schema": "continuous-lease-ready/1",
            "envelope_sha256": sha256(_bytes(self._frame)).hexdigest(),
            "child_pid": os.getpid(),
            "instance_nonce": instance_nonce,
            "scope_sha256": scope.semantic_sha256,
            "lease": _lease_fields(lease),
            "control_sha256": rows.control["semantic_sha256"],
        }
        self._ready, self._lease = ready, lease
        _publish(self.worker.process_directory / "lease-ready.json", ready)
        path = self.worker.process_directory / "parent-accepted.json"
        while not path.exists():
            if self.worker.stop_requested() or time.monotonic() >= self._frame["startup_deadline"]:
                _fail()
            time.sleep(0.01)
        if _read(path) != {
            "schema": "continuous-parent-accepted/1",
            "ready_sha256": sha256(_bytes(ready)).hexdigest(),
        }:
            _fail()
        database.engine.dispose()

    def begin_release(self, payload: bytes) -> None:
        if (
            self._ready is None
            or self._lease is None
            or self._result is not None
            or self.worker.stop_requested()
            or type(payload) is not bytes
            or not 0 < len(payload) <= self.worker.request.limits.receipt_bytes
        ):
            _fail()
        result = {
            "schema": "continuous-result-ready/1",
            "ready_sha256": sha256(_bytes(self._ready)).hexdigest(),
            "result_sha256": sha256(payload).hexdigest(),
            "result_bytes": len(payload),
        }
        _publish(self.worker.process_directory / "result-ready.json", result)
        self._result = result

    def completed(self, payload: bytes, *, release: AccountLeaseRelease) -> None:
        if (
            self._ready is None
            or self._lease is None
            or self._completed
            or self._result is None
            or type(release) is not AccountLeaseRelease
            or release.fence != self._lease.fence
            or release.lease_sha256 != self._lease.semantic_sha256
            or type(payload) is not bytes
            or not 0 < len(payload) <= self.worker.request.limits.receipt_bytes
            or self.worker.stop_requested()
            or sha256(payload).hexdigest() != self._result["result_sha256"]
            or len(payload) != self._result["result_bytes"]
        ):
            _fail()
        value = {
            "schema": "continuous-lease-released/1",
            "ready_sha256": sha256(_bytes(self._ready)).hexdigest(),
            "release_id": release.release_id,
            "release_sha256": release.semantic_sha256,
            "released_at": release.released_at.isoformat(),
            "result_sha256": sha256(payload).hexdigest(),
            "result_bytes": len(payload),
        }
        _publish(self.worker.process_directory / "lease-released.json", value)
        self._completed = True
