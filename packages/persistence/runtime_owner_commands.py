"""Retain authenticated local requests, without applying or authorizing assignments.

Dependency references remain opaque here. A separate concrete reader must resolve
actual account, hold, reconciliation and owner dependencies before it can issue a
VerifiedRuntimeAssignmentCommand. Historical request reads preserve original
expired authentication facts; they never renew a session or command deadline.
"""

from dataclasses import dataclass, field, fields, is_dataclass
from typing import ClassVar, TypeVar
from weakref import WeakValueDictionary, finalize

from sqlalchemy import Connection, Engine

from packages.application.runtime_owner_authentication import (
    AuthenticatedRuntimeOwnerCommand,
    RuntimeOwnerAuthenticator,
)
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.durable_journal_contracts import (
    MAX_APPEND_BYTES,
    MAX_RECORD_BYTES,
    JournalAppend,
    JournalHead,
    JournalKey,
    JournalReceipt,
    JournalRecord,
    journal_identifier,
)
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.domain.research_job_contracts import ResearchRecordCodec
from packages.domain.runtime_owner_contracts import RuntimeOwnerAuthentication
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand, RuntimeReadBudget
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.detached_journal_capture import (
    DetachedJournalCapture,
    detached_journal_value,
)
from packages.persistence.durable_journal import (
    JournalReadSnapshot,
    PreparedJournalAppend,
    ResolvedJournalRead,
    SqlDurableJournal,
)

OWNER_COMMAND_SCHEMA = "runtime-owner-command/1"
OWNER_DEPENDENCIES_SCHEMA = "runtime-owner-dependencies/1"
MAX_OWNER_SNAPSHOT_BYTES = MAX_RECORD_BYTES + MAX_APPEND_BYTES + 2 * MAX_RECORD_BYTES + 16 * 1024
MAX_OWNER_METADATA_BYTES = 2 * 1024 * 1024


class RuntimeOwnerCommandError(ValueError):
    """Static retained-request scope, ownership or integrity failure."""


@dataclass(frozen=True, slots=True)
class RuntimeOwnerCommandRecord(ContractRecord):
    contract_version: ClassVar[str] = "personal-runtime-owner-command/1"
    scope: ContinuousAccountScope
    command: RuntimeAssignmentCommand
    authentication: RuntimeOwnerAuthentication
    dependencies: ContinuousEvidenceRef

    def __post_init__(self) -> None:
        super(RuntimeOwnerCommandRecord, self).__post_init__()
        if (
            self.command.account_id != self.scope.account_id
            or self.command.owner_id != self.authentication.owner_id
            or self.command.semantic_sha256 != self.authentication.command_sha256
            or self.command.requested_at != self.authentication.authenticated_at
            or self.command.expires_at != self.authentication.command_expires_at
            or self.dependencies.schema_id != OWNER_DEPENDENCIES_SCHEMA
            or self.dependencies.object_ref.byte_count > MAX_RECORD_BYTES
            or self.dependencies.semantic_sha256 != self.command.quiescence_sha256
        ):
            raise RuntimeOwnerCommandError("OWNER_REQUEST_AUTHENTICATION_OR_DEPENDENCIES_DIFFER")


def journal_key(scope: ContinuousAccountScope) -> JournalKey:
    if type(scope) is not ContinuousAccountScope:
        raise RuntimeOwnerCommandError("EXACT_OWNER_REQUEST_SCOPE_REQUIRED")
    scope.__post_init__()
    return JournalKey(
        "coordinator",
        "runtime-owner-requests/1",
        scope.account_id,
        "local-owner-session",
        "synthetic",
        scope.semantic_sha256,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedRuntimeOwnerCommand:
    record: RuntimeOwnerCommandRecord
    authenticated: AuthenticatedRuntimeOwnerCommand
    append: PreparedJournalAppend
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RuntimeOwnerCommandSnapshot:
    scope: ContinuousAccountScope
    command_id: str
    journal: JournalReadSnapshot
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedRuntimeOwnerCommand:
    record: RuntimeOwnerCommandRecord
    read: ResolvedJournalRead
    seal: object = field(repr=False, compare=False)


Owned = TypeVar(
    "Owned", PreparedRuntimeOwnerCommand, RuntimeOwnerCommandSnapshot, ResolvedRuntimeOwnerCommand
)


def _identity_graph(
    value: object,
) -> tuple[tuple[object | None, tuple[tuple[str, object], ...]], ...]:
    """Retain field identities; SQL checks these without serializing their contents."""
    pending = [value]
    seen: set[int] = set()
    result = []
    while pending:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if is_dataclass(item) and not isinstance(item, type):
            originals = tuple(
                (f.name, getattr(item, f.name))
                for f in fields(item)
                if f.name not in {"_owner", "_validated_values"}
            )
            result.append((None if item is value else item, originals))
            pending.extend(original for _, original in originals)
        elif type(item) is tuple:
            pending.extend(item)
    return tuple(result)


class SqlRuntimeOwnerCommands:
    """One bounded REQUEST journal. Account assignment and freshness are separate."""

    def __init__(
        self,
        engine: Engine,
        *,
        codec: ResearchRecordCodec,
        authenticator: RuntimeOwnerAuthenticator,
    ) -> None:
        self.engine, self.codec, self.authenticator = engine, codec, authenticator
        self.journal = SqlDurableJournal(
            engine, codec=codec, record_types={OWNER_COMMAND_SCHEMA: RuntimeOwnerCommandRecord}
        )
        self._seal = object()
        self._owned: WeakValueDictionary[int, object] = WeakValueDictionary()
        self._original: dict[
            int, tuple[tuple[object | None, tuple[tuple[str, object], ...]], ...]
        ] = {}
        self._fingerprints: dict[int, str] = {}

    def _own(self, value: Owned) -> Owned:
        self._owned[id(value)] = value
        self._original[id(value)] = _identity_graph(value)
        finalize(value, self._original.pop, id(value), None)
        return value

    def _require(self, value: Owned, expected: type[Owned]) -> None:
        if (
            type(value) is not expected
            or value.seal is not self._seal
            or (self._owned.get(id(value)) is not value)
        ):
            raise RuntimeOwnerCommandError("OWNED_ORIGINAL_OWNER_REQUEST_REQUIRED")
        for item, originals in self._original[id(value)]:
            if any(
                getattr(value if item is None else item, name) is not original
                for name, original in originals
            ):
                raise RuntimeOwnerCommandError("ORIGINAL_OWNER_REQUEST_FIELDS_CHANGED")

    @staticmethod
    def _fingerprint(value: PreparedRuntimeOwnerCommand | ResolvedRuntimeOwnerCommand) -> str:
        graph = value.append if isinstance(value, PreparedRuntimeOwnerCommand) else value.read
        return content_digest((value.record, detached_journal_value(graph)))

    def _remember(self, value: PreparedRuntimeOwnerCommand | ResolvedRuntimeOwnerCommand) -> None:
        self._fingerprints[id(value)] = self._fingerprint(value)
        finalize(value, self._fingerprints.pop, id(value), None)

    def prepare(
        self,
        scope: ContinuousAccountScope,
        *,
        command: RuntimeAssignmentCommand,
        authenticated: AuthenticatedRuntimeOwnerCommand,
        dependencies: ContinuousEvidenceRef,
        expected_head: JournalHead,
    ) -> PreparedRuntimeOwnerCommand:
        """Check actual issuer content and prepare all bytes before account SQL."""
        try:
            self.authenticator.require_authenticated(authenticated)
            record = RuntimeOwnerCommandRecord(
                scope, command, authenticated.authentication, dependencies
            )
            payload = self.codec.encode_record(record)
            if type(payload) is not bytes or not 0 < len(payload) <= MAX_RECORD_BYTES:
                raise RuntimeOwnerCommandError("OWNER_REQUEST_RECORD_BYTE_LIMIT")
            append = self.journal.prepare_append(
                journal_key(scope),
                JournalAppend(
                    command.command_id,
                    command.semantic_sha256,
                    expected_head,
                    (JournalRecord(command.command_id, OWNER_COMMAND_SCHEMA, payload),),
                ),
            )
            result = self._own(
                PreparedRuntimeOwnerCommand(record, authenticated, append, self._seal)
            )
            self._remember(result)
            return result
        except RuntimeOwnerCommandError:
            raise
        except Exception:
            raise RuntimeOwnerCommandError("OWNER_REQUEST_PREPARATION_FAILED") from None

    def require_prepared(self, value: PreparedRuntimeOwnerCommand) -> None:
        """Full graph and authenticator checks are exclusively outside SQL."""
        self._require(value, PreparedRuntimeOwnerCommand)
        try:
            self.authenticator.require_authenticated(value.authenticated)
            if self._fingerprints.get(id(value)) != self._fingerprint(value):
                raise RuntimeOwnerCommandError("ORIGINAL_OWNER_REQUEST_CONTENT_CHANGED")
        except RuntimeOwnerCommandError:
            raise
        except Exception:
            raise RuntimeOwnerCommandError("ORIGINAL_OWNER_AUTHENTICATION_CHANGED") from None

    def append_in_transaction(
        self, connection: Connection, prepared: PreparedRuntimeOwnerCommand
    ) -> JournalReceipt:
        """Cheap original token check; retain REQUEST only in the caller's transaction.

        The shared journal retains its bounded hash integrity checks. No wrapper
        codec, object I/O, authenticator, or full graph fingerprint runs here.
        """
        self._require(prepared, PreparedRuntimeOwnerCommand)
        try:
            return self.journal.append_in_transaction(connection, prepared.append)
        except Exception:
            raise RuntimeOwnerCommandError("OWNER_REQUEST_APPEND_FAILED") from None

    def capture_in_transaction(
        self,
        connection: Connection,
        scope: ContinuousAccountScope,
        *,
        command_id: str,
        budget: RuntimeReadBudget,
    ) -> RuntimeOwnerCommandSnapshot:
        """Detach and charge all selected/auxiliary rows before any decoding.

        Each physical capture charges the caller's shared aggregate budget; rows
        repeated inside that snapshot are interned and charged once.
        """
        try:
            if type(budget) is not RuntimeReadBudget:
                raise RuntimeOwnerCommandError("SHARED_OWNER_REQUEST_READ_BUDGET_REQUIRED")
            journal_identifier(command_id)
            pool = DetachedJournalCapture(
                max_bytes=MAX_OWNER_SNAPSHOT_BYTES, max_metadata_bytes=MAX_OWNER_METADATA_BYTES
            )
            snapshot = pool.capture(
                self.journal.capture_in_transaction(
                    connection, journal_key(scope), command_id=command_id
                )
            )
            budget.charge(len(pool.rows), pool.byte_count, pool.metadata_bytes)
            return self._own(RuntimeOwnerCommandSnapshot(scope, command_id, snapshot, self._seal))
        except RuntimeOwnerCommandError:
            raise
        except Exception:
            raise RuntimeOwnerCommandError("OWNER_REQUEST_CAPTURE_FAILED") from None

    def resolve_snapshot(
        self, snapshot: RuntimeOwnerCommandSnapshot
    ) -> ResolvedRuntimeOwnerCommand | None:
        """Validate exact original record after SQL; no session reauthentication."""
        self._require(snapshot, RuntimeOwnerCommandSnapshot)
        try:
            read = self.journal.resolve_snapshot(snapshot.journal)
            receipt = read.receipt
            if receipt is None:
                return None
            rows = snapshot.journal.requested_receipt
            if rows is None or len(rows.entries) != 1:
                raise RuntimeOwnerCommandError("OWNER_REQUEST_EXACT_ONE_RECORD_REQUIRED")
            row = rows.entries[0]
            record = self.codec.decode_record(row["payload"], RuntimeOwnerCommandRecord)
            if (
                type(record) is not RuntimeOwnerCommandRecord
                or record.scope != snapshot.scope
                or record.command.command_id != snapshot.command_id
                or receipt.command_sha256 != record.command.semantic_sha256
                or row["schema_id"] != OWNER_COMMAND_SCHEMA
                or receipt.record_ids != (record.command.command_id,)
                or self.codec.encode_record(record) != row["payload"]
            ):
                raise RuntimeOwnerCommandError("OWNER_REQUEST_ORIGINAL_RECORD_DIFFERS")
            result = self._own(ResolvedRuntimeOwnerCommand(record, read, self._seal))
            self._remember(result)
            return result
        except RuntimeOwnerCommandError:
            raise
        except Exception:
            raise RuntimeOwnerCommandError("OWNER_REQUEST_RESOLUTION_FAILED") from None

    def read(
        self, scope: ContinuousAccountScope, *, command_id: str, budget: RuntimeReadBudget
    ) -> ResolvedRuntimeOwnerCommand | None:
        with _repeatable_read_transaction(self.engine) as connection:
            snapshot = self.capture_in_transaction(
                connection, scope, command_id=command_id, budget=budget
            )
        return self.resolve_snapshot(snapshot)

    def require_resolved(self, value: ResolvedRuntimeOwnerCommand) -> None:
        self._require(value, ResolvedRuntimeOwnerCommand)
        if self._fingerprints.get(id(value)) != self._fingerprint(value):
            raise RuntimeOwnerCommandError("ORIGINAL_OWNER_REQUEST_CONTENT_CHANGED")

    def recheck_in_transaction(
        self, connection: Connection, value: ResolvedRuntimeOwnerCommand
    ) -> JournalReceipt:
        """Recheck original retained request; later appends never refresh its time."""
        self._require(value, ResolvedRuntimeOwnerCommand)
        try:
            _, receipt = self.journal.recheck_in_transaction(
                connection, value.read, require_current_head=False
            )
            if receipt is None:
                raise RuntimeOwnerCommandError("OWNER_REQUEST_ORIGINAL_RECEIPT_MISSING")
            return receipt
        except RuntimeOwnerCommandError:
            raise
        except Exception:
            raise RuntimeOwnerCommandError("OWNER_REQUEST_RECHECK_FAILED") from None
