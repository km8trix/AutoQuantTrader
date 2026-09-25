"""Caller-transaction daily simulation admissions; no dispatch or re-arm.

The required producer reader is an explicit composition dependency. No default
reader treats supplied snapshots, availability flags or owner claims as evidence.
The versioned detached profile blocks any legacy reservation history until its
separately reviewed bridge exists.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from itertools import pairwise
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar, Literal, Protocol, TypeVar, cast
from weakref import WeakValueDictionary, finalize
from zoneinfo import ZoneInfo

import sqlalchemy as sa
from sqlalchemy import Connection, Engine

from packages.application.daily_commitment_install import prepare_daily_commitments
from packages.application.daily_runtime_activation import prepare_daily_runtime_activation
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    AccountingState,
    AccountSnapshot,
    Commitment,
    ExecutionAccountingPort,
    ExecutionPolicy,
    ReleaseRuntimeUnsent,
)
from packages.domain.continuous_engine_contracts import ContinuousEngineInputs
from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
from packages.domain.continuous_reconciliation_contracts import ContinuousReconciliationBatch
from packages.domain.daily_attempt import advance_daily_attempt, reduce_daily_attempt
from packages.domain.daily_attempt_contracts import (
    CanonicalDailyAttempt,
    DailyAttemptEnvelope,
    DailyAttemptPreparation,
    DailyFenceReference,
)
from packages.domain.daily_observed_hold_contracts import (
    DailyObservedHoldGroup,
    DailyObservedHoldResult,
    RuntimeObservedHoldInputs,
    daily_runtime_attempt_prefix,
    daily_runtime_effect_watermark,
)
from packages.domain.daily_risk import evaluate_daily_risk
from packages.domain.daily_runtime_contracts import (
    RuntimeCommitmentBinding,
    RuntimeObligationInventory,
    RuntimeProducerMap,
    RuntimeRiskAdmission,
    RuntimeRiskAssignment,
    RuntimeRiskInputRefs,
)
from packages.domain.durable_journal_contracts import JournalReceipt
from packages.domain.engine_contracts import DailyIntentBatch, DailyRiskDecision, DailyRiskPolicy
from packages.domain.operational_control import (
    OperationalControlState,
    OperationalControlTransition,
)
from packages.domain.personal_contracts import (
    ContractRecord,
    VersionPin,
    content_digest,
    require_digest,
)
from packages.domain.reconciliation_contracts import (
    ReconciliationHeads,
    ReconciliationPolicy,
    ReconciliationResult,
)
from packages.domain.research_job_contracts import ResearchRecordCodec, require_identifier
from packages.domain.submission_attempt import SubmissionAttemptState
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    lock_account_capacity_serialization,
)
from packages.persistence.continuous_account_schema import (
    continuous_account_commits,
    continuous_account_heads,
)
from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_admissions as admissions,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_assignment_heads as assignment_heads,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_assignments as assignments,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_attempt_events as attempt_events,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_attempt_heads as attempt_heads,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_consumptions as consumptions,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_hold_events as hold_events,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_hold_heads as hold_heads,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_observed_hold_groups as observed_hold_groups,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_outbound as outbound,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.durable_journal import PreparedJournalAppend, SqlDurableJournal
from packages.persistence.immutable import as_aware_utc
from packages.persistence.operational_control import (
    _completion_rows_index,
    _verified_history_from_rows,
    resolve_operational_control_rows,
)
from packages.persistence.schema import (
    phase2_batch_reservations,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)

if TYPE_CHECKING:
    from packages.persistence.continuous_runtime_attempt_sources import (
        ResolvedCommittedContinuousRuntimeAttemptSources,
    )

MAX_ROWS = 4096
MAX_BYTES = 1024 * 1024
PROJECTION_PIN = VersionPin(
    "daily_runtime_hold",
    "personal-daily-runtime-risk/1",
    content_digest("canonical-prepared-daily-commitment/1"),
)


class DailyRuntimeRiskConflict(ValueError):
    """Exact durable identities or current account evidence do not match."""


@dataclass(frozen=True, slots=True)
class RuntimeAssignmentCommand(ContractRecord):
    contract_version: ClassVar[str] = "personal-daily-assignment-command/1"
    command_id: str
    owner_id: str
    account_id: str
    before_assignment_sha256: str | None
    after_assignment_sha256: str
    expected_heads: ReconciliationHeads
    quiescence_sha256: str
    requested_at: datetime
    expires_at: datetime
    runtime_environment: Literal["stateful_simulation"] = "stateful_simulation"

    def __post_init__(self) -> None:
        super(RuntimeAssignmentCommand, self).__post_init__()
        for name in ("command_id", "owner_id", "account_id"):
            require_identifier(getattr(self, name), name)
        for value in (self.after_assignment_sha256, self.quiescence_sha256):
            require_digest(value, "assignment command reference")
        if self.before_assignment_sha256 is not None:
            require_digest(self.before_assignment_sha256, "previous assignment")
        if self.expires_at <= self.requested_at:
            raise ValueError("owner command requires a bounded validity interval")


@dataclass(frozen=True, slots=True)
class VerifiedRuntimeAssignmentCommand(ContractRecord):
    """Reader output after resolving the retained owner/quiescence records."""

    command: RuntimeAssignmentCommand
    current_heads: ReconciliationHeads
    reconciliation: ReconciliationResult | None


@dataclass(frozen=True, slots=True)
class ResolvedRuntimeRiskInputs(ContractRecord):
    state: AccountingState
    snapshot: AccountSnapshot
    inputs: RuntimeRiskInputRefs
    producer_map: RuntimeProducerMap
    context: AccountingContext
    execution_policy: ExecutionPolicy


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeAttemptAccountingSource(ContractRecord):
    """Retained inputs, not a passing result; a required producer authenticates closure."""

    contract_version: ClassVar[str] = "daily-attempt-accounting-source/1"
    account_id: str
    coordinator_command_id: str
    coordinator_sequence: int
    state: AccountingState
    context: AccountingContext
    execution_policy: ExecutionPolicy
    obligations: RuntimeObligationInventory
    heads: ReconciliationHeads
    fence: DailyFenceReference
    checked_at: datetime
    valid_until: datetime
    accounting_command: AccountingCommand | None
    source_references: tuple[ContinuousEvidenceRef, ...]

    def __post_init__(self) -> None:
        super(RuntimeAttemptAccountingSource, self).__post_init__()
        require_identifier(self.account_id, "attempt account")
        require_identifier(self.coordinator_command_id, "coordinator command")
        if (
            not 1 <= self.coordinator_sequence < 2**63
            or self.state.account_id != self.account_id
            or self.fence.fence.account_id != self.account_id
            or not self.fence.validated_at
            <= self.checked_at
            < self.valid_until
            <= self.fence.valid_until
            or self.context.point.knowledge_at != self.checked_at
            or self.execution_policy.model_id != "observed-facts-v1"
            or self.heads.capacity_sha256 != self.obligations.semantic_sha256
            or self.heads.lease_generation != self.fence.fence.fencing_generation
            or not 1 <= len(self.source_references) <= 32
            or len(set(self.source_references)) != len(self.source_references)
        ):
            raise ValueError("daily attempt source scope, time or original closure differs")


def daily_attempt_inventory_sha256(attempts: tuple[CanonicalDailyAttempt, ...]) -> str:
    if len({item.attempt_id for item in attempts}) != len(attempts):
        raise DailyRuntimeRiskConflict("attempt inventory duplicates an identity")
    return content_digest(
        ("daily-attempt-inventory/1", tuple(sorted(attempts, key=lambda item: item.attempt_id)))
    )


SQL_PROFILE = "personal-daily-sql-detached/1"
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_TOTAL_ROWS = 16384
CONTROL_TABLES = (
    phase5_operational_control_transitions,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
)


@dataclass(slots=True)
class RuntimeReadBudget:
    payload_bytes: int = 0
    metadata_bytes: int = 0
    rows: int = 0
    captured: list[RuntimeTableSnapshot] = field(default_factory=list, repr=False)

    def charge(self, rows: int, payload: int, metadata: int) -> None:
        if min(rows, payload, metadata) < 0 or rows > MAX_ROWS:
            raise DailyRuntimeRiskConflict("daily table row bound exceeded")
        self.rows += rows
        self.payload_bytes += payload
        self.metadata_bytes += metadata
        if (
            self.rows > MAX_TOTAL_ROWS
            or self.payload_bytes > MAX_TOTAL_BYTES
            or self.metadata_bytes > MAX_METADATA_BYTES
        ):
            raise DailyRuntimeRiskConflict("daily aggregate capture bound exceeded")


@dataclass(frozen=True, slots=True)
class RuntimeTableSnapshot:
    table: sa.Table
    account_id: str
    rows: tuple[Mapping[str, Any], ...]


def _require_same_runtime_tables(
    original: tuple[RuntimeTableSnapshot, ...],
    fresh: tuple[RuntimeTableSnapshot, ...],
    *,
    comparison: ContinuousCaptureComparison,
) -> None:
    """Complete primitive rows, after the enclosing owners authenticate captures."""
    if type(comparison) is not ContinuousCaptureComparison:
        raise DailyRuntimeRiskConflict("exact bounded capture comparison required")
    for before, after in comparison.pairs(original, fresh):
        if type(before) is not RuntimeTableSnapshot or type(after) is not RuntimeTableSnapshot:
            raise DailyRuntimeRiskConflict("exact runtime table capture required")
        comparison.identity(before.table, after.table)
        comparison.data(before.account_id, after.account_id)
        comparison.data(before.rows, after.rows)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RuntimeProducerRawSnapshot:
    tables: tuple[RuntimeTableSnapshot, ...]


class RuntimeProducerReader(Protocol):
    def capture_in_transaction(
        self,
        connection: Connection,
        *,
        account_id: str,
        refs: RuntimeRiskInputRefs | None,
        owner_command_ref: JournalReceipt | None,
        budget: RuntimeReadBudget,
    ) -> RuntimeProducerRawSnapshot:
        """Fixed bounded SQL capture only, using capture_runtime_table and shared budget."""
        ...

    def resolve(
        self,
        snapshot: RuntimeProducerRawSnapshot,
        *,
        assignment: RuntimeRiskAssignment | None,
        previous: RuntimeRiskAssignment | None,
        refs: RuntimeRiskInputRefs | None,
        owner_command_ref: JournalReceipt | None,
        fence_receipt: AccountFenceReceipt,
        control: OperationalControlTransition | None,
    ) -> ResolvedRuntimeRiskInputs | VerifiedRuntimeAssignmentCommand | None:
        """Authenticate source/owner bytes after the capture transaction has closed."""
        ...

    def recheck_in_transaction(
        self, connection: Connection, snapshot: RuntimeProducerRawSnapshot
    ) -> None:
        """Fixed bounded metadata checks only; never codec/accounting/source resolution."""
        ...


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RuntimeAttemptSourcePlan:
    references: tuple[ContinuousEvidenceRef, ...]
    state: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RuntimeAttemptSourceSnapshot:
    plan: RuntimeAttemptSourcePlan
    tables: tuple[RuntimeTableSnapshot, ...]
    state: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedRuntimeAttemptSources:
    snapshot: RuntimeAttemptSourceSnapshot
    sources: tuple[RuntimeAttemptAccountingSource, ...]
    state: object = field(repr=False, compare=False)


class RuntimeAttemptProducerReader(Protocol):
    """Required additional methods on the same producers instance; no permissive default.

    The producer owns and authenticates its exact plan/raw/resolved tokens. It
    verifies retained parent/checkpoint/source/fence closure, including outcomes
    and owner commands, independently of these presentation constructors.
    """

    def prepare_attempt_source_read(
        self, references: tuple[ContinuousEvidenceRef, ...]
    ) -> RuntimeAttemptSourcePlan: ...

    def capture_attempt_sources_in_transaction(
        self,
        connection: Connection,
        plan: RuntimeAttemptSourcePlan,
        *,
        account_id: str,
        budget: RuntimeReadBudget,
    ) -> RuntimeAttemptSourceSnapshot: ...

    def resolve_attempt_sources(
        self,
        snapshot: RuntimeAttemptSourceSnapshot,
        *,
        admissions: tuple[RetainedDailyAdmission, ...],
    ) -> ResolvedRuntimeAttemptSources: ...

    def recheck_attempt_sources_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedRuntimeAttemptSources,
    ) -> None: ...

    def require_same_attempt_capture(
        self,
        original: ResolvedRuntimeAttemptSources,
        fresh: RuntimeAttemptSourceSnapshot,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None: ...


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RuntimeObservedHoldSourcePlan:
    references: tuple[ContinuousEvidenceRef, ...]
    state: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RuntimeObservedHoldSourceSnapshot:
    plan: RuntimeObservedHoldSourcePlan
    tables: tuple[RuntimeTableSnapshot, ...]
    state: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedRuntimeObservedHoldSources:
    snapshot: RuntimeObservedHoldSourceSnapshot
    inputs: tuple[RuntimeObservedHoldInputs, ...]
    state: object = field(repr=False, compare=False)


class RuntimeObservedHoldProducerReader(Protocol):
    """Mandatory same-producer original venue/sole-engine closure authentication."""

    def prepare_observed_hold_source_read(
        self, references: tuple[ContinuousEvidenceRef, ...]
    ) -> RuntimeObservedHoldSourcePlan: ...

    def capture_observed_hold_sources_in_transaction(
        self,
        connection: Connection,
        plan: RuntimeObservedHoldSourcePlan,
        *,
        account_id: str,
        budget: RuntimeReadBudget,
    ) -> RuntimeObservedHoldSourceSnapshot: ...

    def resolve_observed_hold_sources(
        self,
        snapshot: RuntimeObservedHoldSourceSnapshot,
        *,
        admissions: tuple[RetainedDailyAdmission, ...],
    ) -> ResolvedRuntimeObservedHoldSources: ...

    def recheck_observed_hold_sources_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedRuntimeObservedHoldSources,
    ) -> None: ...

    def require_same_observed_capture(
        self,
        original: ResolvedRuntimeObservedHoldSources,
        fresh: RuntimeObservedHoldSourceSnapshot,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None: ...


@dataclass(frozen=True, slots=True, weakref_slot=True)
class DailyRuntimeRawSnapshot:
    account_id: str
    receipt: AccountFenceReceipt
    tables: tuple[RuntimeTableSnapshot, ...]
    producer: RuntimeProducerRawSnapshot
    command_id: str | None
    input_refs: RuntimeRiskInputRefs | None
    owner_command_ref: JournalReceipt | None
    seal: object = field(repr=False, compare=False)
    attempt_sources: RuntimeAttemptSourceSnapshot | None = None
    requested_envelopes: tuple[DailyAttemptEnvelope, ...] = ()
    requested_preparations: tuple[DailyAttemptPreparation, ...] = ()
    observed_sources: RuntimeObservedHoldSourceSnapshot | None = None
    requested_observed_source: ContinuousEvidenceRef | None = None
    capture_usage: tuple[int, int, int] = (0, 0, 0)


@dataclass(frozen=True, slots=True)
class _AdmissionRecord(ContractRecord):
    command_id: str
    request_sha256: str
    admission: RuntimeRiskAdmission
    resolved: ResolvedRuntimeRiskInputs
    prepared_commitments: tuple[Commitment, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedDailyRuntimeSnapshot:
    raw: DailyRuntimeRawSnapshot
    assignment: RuntimeRiskAssignment | None
    assignment_rows: tuple[RuntimeRiskAssignment, ...]
    admissions: tuple[_AdmissionRecord, ...]
    obligations: RuntimeObligationInventory
    control: OperationalControlTransition | None
    seal: object = field(repr=False, compare=False)
    attempts: tuple[CanonicalDailyAttempt, ...] = ()
    attempt_envelopes: tuple[DailyAttemptEnvelope, ...] = ()
    attempt_sources: ResolvedRuntimeAttemptSources | None = None
    observed_groups: tuple[DailyObservedHoldGroup, ...] = ()
    observed_sources: ResolvedRuntimeObservedHoldSources | None = None


@dataclass(frozen=True, slots=True)
class _Write:
    table: sa.Table
    values: Mapping[str, Any]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedDailyAdmission:
    snapshot: ResolvedDailyRuntimeSnapshot
    result: RuntimeRiskAdmission
    writes: tuple[_Write, ...]
    valid_until: datetime | None
    retry: bool
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedDailyAssignment:
    snapshot: ResolvedDailyRuntimeSnapshot
    result: RuntimeRiskAssignment
    writes: tuple[_Write, ...]
    head_values: Mapping[str, Any]
    valid_until: datetime
    retry: bool
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RetainedDailyAdmission:
    """Owned detached inspection; the existing enclosing codec identity is unchanged."""

    command_id: str
    request_sha256: str
    record_sha256: str
    canonical_payload: bytes
    payload_sha256: str
    admission: RuntimeRiskAdmission
    resolved: ResolvedRuntimeRiskInputs
    prepared_commitments: tuple[Commitment, ...]
    bindings: tuple[RuntimeCommitmentBinding, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class HistoricalDailyAdmissionSnapshot:
    account_id: str
    command_id: str
    expected_record_sha256: str
    tables: tuple[RuntimeTableSnapshot, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedHistoricalDailyAdmission:
    snapshot: HistoricalDailyAdmissionSnapshot
    admission: RetainedDailyAdmission


@dataclass(frozen=True, slots=True)
class DailyAttemptMutationResult(ContractRecord):
    coordinator_command_id: str
    coordinator_sequence: int
    attempts: tuple[CanonicalDailyAttempt, ...]
    obligations: RuntimeObligationInventory
    accounting_state: AccountingState


@dataclass(frozen=True, slots=True)
class _HeadUpdate:
    table: sa.Table
    previous: Mapping[str, Any] | None
    values: Mapping[str, Any]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedDailyAttemptMutation:
    snapshot: ResolvedDailyRuntimeSnapshot
    result: DailyAttemptMutationResult
    writes: tuple[_Write, ...]
    head_updates: tuple[_HeadUpdate, ...]
    valid_until: datetime | None
    retry: bool
    journal: SqlDurableJournal | None = field(repr=False, compare=False)
    dispatch_appends: tuple[PreparedJournalAppend, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedDailyObservedHolds:
    snapshot: ResolvedDailyRuntimeSnapshot
    result: DailyObservedHoldResult
    writes: tuple[_Write, ...]
    head_updates: tuple[_HeadUpdate, ...]
    valid_until: datetime | None
    retry: bool


@dataclass(frozen=True, slots=True)
class _ObservedHistoricalRows:
    snapshot: RuntimeTableSnapshot
    predicates: tuple[Any, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RetainedDailyObservedHolds:
    """Owned original financial result and immutable source/row prefix."""

    result: DailyObservedHoldResult
    inputs: RuntimeObservedHoldInputs
    sources: ResolvedRuntimeObservedHoldSources
    selected: tuple[_ObservedHistoricalRows, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RetainedDailyAttemptGroup:
    """Original canonical attempt result with immutable source and financial prefix."""

    result: DailyAttemptMutationResult
    source: RuntimeAttemptAccountingSource
    envelopes: tuple[DailyAttemptEnvelope, ...]
    sources: ResolvedRuntimeAttemptSources
    selected: tuple[_ObservedHistoricalRows, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RetainedDailyAssignmentPrefix:
    """Owned B query results; C must authenticate the cutoff and complete hold IDs."""

    snapshot: ResolvedDailyRuntimeSnapshot
    before_assignment: RuntimeRiskAssignment | None
    after_assignment: RuntimeRiskAssignment
    command: RuntimeAssignmentCommand
    recorded_at: datetime
    through_coordinator_sequence: int
    commitment_ids: tuple[str, ...]
    obligations: RuntimeObligationInventory
    attempts: tuple[CanonicalDailyAttempt, ...]
    attempt_envelopes: tuple[DailyAttemptEnvelope, ...]
    observed_groups: tuple[DailyObservedHoldGroup, ...]
    control: OperationalControlTransition | None
    selected: tuple[_ObservedHistoricalRows, ...]


T = TypeVar("T", bound=ContractRecord)
Owned = TypeVar(
    "Owned",
    DailyRuntimeRawSnapshot,
    ResolvedDailyRuntimeSnapshot,
    PreparedDailyAdmission,
    PreparedDailyAssignment,
    RetainedDailyAdmission,
    HistoricalDailyAdmissionSnapshot,
    ResolvedHistoricalDailyAdmission,
    PreparedDailyAttemptMutation,
    PreparedDailyObservedHolds,
    RetainedDailyObservedHolds,
    RetainedDailyAttemptGroup,
    RetainedDailyAssignmentPrefix,
)


def _field(column: sa.Column[Any]) -> tuple[str, int, bool]:
    if isinstance(column.type, sa.LargeBinary):
        return "blob", MAX_BYTES, True
    if isinstance(column.type, sa.String):
        return "text", column.type.length or MAX_BYTES, column.type.length is None
    if isinstance(column.type, sa.DateTime):
        return "datetime", 64, False
    if isinstance(column.type, sa.Date):
        return "date", 16, False
    if isinstance(column.type, sa.Boolean):
        return "boolean", 8, False
    if isinstance(column.type, sa.Integer):
        return "integer", 24, False
    if isinstance(column.type, sa.Numeric):
        return "decimal", 128, False
    raise DailyRuntimeRiskConflict("unsupported bounded SQL field")


def _expressions(column: sa.Column[Any], connection: Connection) -> tuple[Any, Any, Any, bool]:
    kind, limit, payload = _field(column)
    sqlite = connection.dialect.name == "sqlite"
    cast_text = sa.cast(column, sa.String())
    length = (
        sa.func.length(sa.cast(column, sa.LargeBinary()))
        if sqlite
        else sa.func.octet_length(column if kind == "blob" else cast_text)
    )
    value: Any
    if kind in ("blob", "text", "datetime", "date"):
        typed = (
            sa.func.typeof(column) == ("blob" if kind == "blob" else "text")
            if sqlite
            else sa.true()
        )
        valid = sa.and_(typed, length <= limit)
        raw = column if kind in ("blob", "text") else cast_text
        value = sa.func.substr(raw, 1, limit + 1)
    elif kind in ("integer", "boolean"):
        valid = sa.func.typeof(column) == "integer" if sqlite else sa.true()
        if kind == "boolean":
            valid = sa.and_(valid, sa.cast(column, sa.Integer()).in_((0, 1)))
        # PostgreSQL supports Boolean -> INTEGER, while integer metadata must
        # retain its existing BIGINT range. Both projections yield Python ints.
        value = sa.cast(column, sa.Integer() if kind == "boolean" else sa.BigInteger())
    else:
        valid = sa.and_(
            sa.func.typeof(column).in_(("integer", "real")) if sqlite else sa.true(),
            length <= limit,
        )
        value = column
    valid = (
        sa.or_(column.is_(None), valid) if column.nullable else sa.and_(column.is_not(None), valid)
    )
    return valid, sa.case((valid, value), else_=None), sa.func.coalesce(length, 0), payload


def capture_runtime_table(
    connection: Connection, table: sa.Table, *, account_id: str, budget: RuntimeReadBudget
) -> RuntimeTableSnapshot:
    """Transfer-bounded fixed-table capture; no Python decoders or reducers."""
    return _capture_runtime_rows(connection, table, account_id=account_id, budget=budget)


def _capture_runtime_rows(
    connection: Connection,
    table: sa.Table,
    *,
    account_id: str,
    budget: RuntimeReadBudget,
    extra: tuple[Any, ...] = (),
) -> RuntimeTableSnapshot:
    if "account_id" not in table.c or not table.primary_key.columns:
        raise DailyRuntimeRiskConflict("captured table requires account and primary key")
    expressions = tuple((c, *_expressions(c, connection)) for c in table.c)
    where = sa.and_(table.c.account_id == account_id, *extra)
    bounded = sa.select(*table.c).where(where).limit(MAX_ROWS + 1).subquery()
    checks = tuple(
        _expressions(cast(sa.Column[Any], bounded.c[column.name]), connection) for column in table.c
    )
    invalid = sa.or_(*(sa.not_(valid) for valid, _, _, _ in checks))
    payload = sum((length for _, _, length, large in checks if large), sa.literal(0))
    metadata = sum((length for _, _, length, large in checks if not large), sa.literal(0))
    count, bad, payload_bytes, metadata_bytes = connection.execute(
        sa.select(
            sa.func.count(),
            sa.func.coalesce(sa.func.sum(sa.case((invalid, 1), else_=0)), 0),
            sa.func.coalesce(sa.func.sum(payload), 0),
            sa.func.coalesce(sa.func.sum(metadata), 0),
        ).select_from(bounded)
    ).one()
    if bad:
        raise DailyRuntimeRiskConflict("invalid or oversized retained SQL field")
    budget.charge(int(count), int(payload_bytes), int(metadata_bytes))
    rows = tuple(
        MappingProxyType(dict(row))
        for row in connection.execute(
            sa.select(*(value.label(column.name) for column, _, value, _, _ in expressions))
            .where(where)
            .order_by(*table.primary_key.columns)
            .limit(MAX_ROWS + 1)
        ).mappings()
    )
    if len(rows) != count:
        raise DailyRuntimeRiskConflict("captured row inventory changed")
    snapshot = RuntimeTableSnapshot(table, account_id, rows)
    budget.captured.append(snapshot)
    return snapshot


def _typed_rows(snapshot: RuntimeTableSnapshot) -> tuple[Mapping[str, Any], ...]:
    result = []
    for row in snapshot.rows:
        converted = dict(row)
        for column in snapshot.table.c:
            value = row[column.name]
            kind, limit, _ = _field(column)
            if value is None:
                if not column.nullable:
                    raise DailyRuntimeRiskConflict("non-null retained field missing")
                continue
            if kind in ("blob", "text", "datetime", "date"):
                if type(value) is not (bytes if kind == "blob" else str) or len(value) > limit:
                    raise DailyRuntimeRiskConflict("retained field type/length differs")
                if kind == "datetime":
                    converted[column.name] = as_aware_utc(datetime.fromisoformat(cast(str, value)))
                elif kind == "date":
                    converted[column.name] = date.fromisoformat(cast(str, value))
            elif kind in ("integer", "boolean"):
                if type(value) is not int or (kind == "boolean" and value not in (0, 1)):
                    raise DailyRuntimeRiskConflict("retained numeric metadata differs")
                if kind == "boolean":
                    converted[column.name] = bool(value)
            elif type(value) is not Decimal:
                raise DailyRuntimeRiskConflict("retained decimal metadata differs")
        result.append(MappingProxyType(converted))
    return tuple(result)


def _recheck_table(
    connection: Connection,
    snapshot: RuntimeTableSnapshot,
    *,
    exact_inventory: bool = True,
) -> None:
    table = snapshot.table
    where = table.c.account_id == snapshot.account_id
    bounded = sa.select(*table.primary_key.columns).where(where).limit(MAX_ROWS + 1).subquery()
    if exact_inventory and connection.scalar(
        sa.select(sa.func.count()).select_from(bounded)
    ) != len(snapshot.rows):
        raise DailyRuntimeRiskConflict("captured row inventory changed")
    columns = tuple((c, *_expressions(c, connection)) for c in table.c)
    chunk = max(1, min(32, 800 // len(columns)))
    for offset in range(0, len(snapshot.rows), chunk):
        rows = snapshot.rows[offset : offset + chunk]
        predicates = []
        for row in rows:
            predicates.append(
                sa.and_(
                    *(
                        sa.and_(
                            valid, value.is_(None) if row[c.name] is None else value == row[c.name]
                        )
                        for c, valid, value, _, _ in columns
                    )
                )
            )
        matching = connection.scalar(
            sa.select(sa.func.count()).select_from(table).where(where, sa.or_(*predicates))
        )
        if matching != len(rows):
            raise DailyRuntimeRiskConflict("captured immutable row bytes changed")


class SqlDailyRuntimeRisk:
    """Bounded detached validation with cheap caller-owned atomic final writes."""

    def __init__(
        self,
        engine: Engine,
        *,
        coordinator: SqlAccountCoordinator,
        codec: ResearchRecordCodec,
        producers: RuntimeProducerReader,
        accounting: ExecutionAccountingPort,
    ) -> None:
        if type(coordinator) is not SqlAccountCoordinator:
            raise ValueError("daily risk requires the exact durable coordinator")
        for port, methods in (
            (producers, ("capture_in_transaction", "resolve", "recheck_in_transaction")),
            (codec, ("encode_record", "decode_record")),
            (accounting, ("advance", "project")),
        ):
            if any(not callable(getattr(port, name, None)) for name in methods):
                raise ValueError("daily risk requires explicit complete integration ports")
        self.engine, self.coordinator, self.codec = engine, coordinator, codec
        self.producers, self.accounting = producers, accounting
        self._seal = object()
        self._resolved_originals: dict[int, tuple[object, ...]] = {}
        self._owned: WeakValueDictionary[int, Any] = WeakValueDictionary()
        self._observed_originals: dict[int, tuple[object, ...]] = {}
        self._observed_contents: dict[int, str] = {}
        self._capture_usage: dict[int, tuple[int, int, int]] = {}
        self._raw_capture_originals: dict[int, tuple[object, ...]] = {}
        self._observed_view_originals: dict[int, tuple[tuple[object, ...], str]] = {}
        self._assignment_originals: dict[int, tuple[tuple[object, ...], str]] = {}
        self._assignment_prefix_originals: dict[int, tuple[tuple[object, ...], str]] = {}
        self._attempt_originals: dict[int, tuple[tuple[object, ...], str]] = {}
        self._admission_originals: dict[int, tuple[tuple[object, ...], str]] = {}

    def _own(self, value: Owned) -> Owned:
        if (
            isinstance(
                value,
                (
                    PreparedDailyAdmission,
                    PreparedDailyAssignment,
                    PreparedDailyAttemptMutation,
                    PreparedDailyObservedHolds,
                ),
            )
            and value.writes
        ):
            self._check_result_bound(value)
        self._owned[id(value)] = value
        if isinstance(value, PreparedDailyAdmission):
            self._admission_originals[id(value)] = (
                self._assignment_identity_fields(value),
                content_digest(value.result),
            )
            finalize(value, self._admission_originals.pop, id(value), None)
        if isinstance(value, ResolvedDailyRuntimeSnapshot):
            self._resolved_originals[id(value)] = self._assignment_identity_fields(value)
            finalize(value, self._resolved_originals.pop, id(value), None)
        if isinstance(value, DailyRuntimeRawSnapshot):
            self._capture_usage[id(value)] = value.capture_usage
            self._raw_capture_originals[id(value)] = self._raw_capture_fields(value)
            finalize(value, self._capture_usage.pop, id(value), None)
            finalize(value, self._raw_capture_originals.pop, id(value), None)
        if isinstance(value, PreparedDailyObservedHolds):
            self._observed_originals[id(value)] = self._observed_fields(value)
            self._observed_contents[id(value)] = self._observed_content_sha256(value)
            finalize(value, self._observed_originals.pop, id(value), None)
            finalize(value, self._observed_contents.pop, id(value), None)
        if isinstance(value, RetainedDailyObservedHolds):
            self._observed_view_originals[id(value)] = (
                self._observed_view_fields(value),
                value.inputs.semantic_sha256,
            )
            finalize(value, self._observed_view_originals.pop, id(value), None)
        if isinstance(value, PreparedDailyAssignment):
            self._assignment_originals[id(value)] = (
                self._assignment_fields(value),
                self._assignment_content(value),
            )
            finalize(value, self._assignment_originals.pop, id(value), None)
        if isinstance(value, RetainedDailyAssignmentPrefix):
            self._assignment_prefix_originals[id(value)] = (
                self._assignment_prefix_fields(value),
                self._assignment_prefix_content(value),
            )
            finalize(value, self._assignment_prefix_originals.pop, id(value), None)
        if isinstance(value, (PreparedDailyAttemptMutation, RetainedDailyAttemptGroup)):
            self._attempt_originals[id(value)] = (
                self._attempt_fields(value),
                self._attempt_content(value),
            )
            finalize(value, self._attempt_originals.pop, id(value), None)
        return value

    @staticmethod
    def _attempt_fields(
        value: PreparedDailyAttemptMutation | RetainedDailyAttemptGroup,
    ) -> tuple[object, ...]:
        return SqlDailyRuntimeRisk._assignment_identity_fields(value)

    @staticmethod
    def _attempt_content(
        value: PreparedDailyAttemptMutation | RetainedDailyAttemptGroup,
    ) -> str:
        sources = (
            value.snapshot.attempt_sources
            if isinstance(value, PreparedDailyAttemptMutation)
            else value.sources
        )
        envelopes = (
            value.snapshot.raw.requested_envelopes
            if isinstance(value, PreparedDailyAttemptMutation)
            else value.envelopes
        )
        return content_digest((value.result, envelopes, () if sources is None else sources.sources))

    def _require_attempt(
        self, value: PreparedDailyAttemptMutation | RetainedDailyAttemptGroup
    ) -> None:
        self._require_owned(value)
        if type(value) not in (PreparedDailyAttemptMutation, RetainedDailyAttemptGroup):
            raise DailyRuntimeRiskConflict("original owned attempt preparation or history required")
        before = self._attempt_originals[id(value)][0]
        current = self._attempt_fields(value)
        if len(before) != len(current) or any(
            a is not b for a, b in zip(before, current, strict=True)
        ):
            raise DailyRuntimeRiskConflict("original attempt fields changed")

    def require_prepared_attempt(self, value: PreparedDailyAttemptMutation) -> None:
        """Check full owned source/result contents outside SQL before publication."""
        if type(value) is not PreparedDailyAttemptMutation:
            raise DailyRuntimeRiskConflict("original owned attempt preparation required")
        self._require_attempt(value)
        if self._attempt_originals[id(value)][1] != self._attempt_content(value):
            raise DailyRuntimeRiskConflict("original attempt contents changed")

    def require_attempt_group_view(self, value: RetainedDailyAttemptGroup) -> None:
        if type(value) is not RetainedDailyAttemptGroup:
            raise DailyRuntimeRiskConflict("original retained attempt group required")
        self._require_attempt(value)
        if self._attempt_originals[id(value)][1] != self._attempt_content(value):
            raise DailyRuntimeRiskConflict("original attempt group contents changed")

    @staticmethod
    def _assignment_fields(value: PreparedDailyAssignment) -> tuple[object, ...]:
        return SqlDailyRuntimeRisk._assignment_identity_fields(value)

    @staticmethod
    def _assignment_identity_fields(value: object) -> tuple[object, ...]:
        """Original field identities only; no canonicalization, codec or object I/O."""
        pending, seen = [value], set()
        retained: list[object] = []
        while pending:
            item = pending.pop()
            if type(item) is tuple:
                # Exact tuples have no dataclass or mapping hooks. Keep their
                # original identity visit and child order without reflection.
                if id(item) in seen:
                    continue
                seen.add(id(item))
                retained.extend(item)
                pending.extend(item)
                continue
            # Parent fields already retain scalar identities. These exact immutable
            # built-in leaves have no graph children; subclasses use the old path.
            item_type = type(item)
            if (
                item_type is str
                or item_type is int
                or item_type is bytes
                or item_type is type(None)
                or item_type is bool
                or item_type is Decimal
                or item_type is datetime
                or item_type is date
                or item_type is object
            ):
                continue
            if id(item) in seen:
                continue
            seen.add(id(item))
            if is_dataclass(item) and not isinstance(item, type):
                nested = tuple(getattr(item, f.name) for f in fields(item))
            elif isinstance(item, Mapping):
                nested = tuple(v for pair in item.items() for v in pair)
            else:
                continue
            retained.extend(nested)
            pending.extend(nested)
        return tuple(retained)

    @staticmethod
    def _assignment_content(value: PreparedDailyAssignment) -> str:
        snapshot = value.snapshot
        return content_digest(
            (
                value.result,
                snapshot.assignment_rows,
                snapshot.obligations,
                snapshot.control,
                snapshot.attempts,
                snapshot.attempt_envelopes,
                snapshot.observed_groups,
            )
        )

    def require_prepared_assignment(self, value: PreparedDailyAssignment) -> None:
        """Original assignment graph check outside SQL, with no renewed authority."""
        self._require_prepared_assignment(value)
        if self._assignment_originals[id(value)][1] != self._assignment_content(value):
            raise DailyRuntimeRiskConflict("original assignment preparation contents changed")

    def _require_prepared_admission(self, value: PreparedDailyAdmission) -> None:
        self._require_owned(value)
        if type(value) is not PreparedDailyAdmission or value.seal is not self._seal:
            raise DailyRuntimeRiskConflict("original admission preparation required")
        before = self._admission_originals[id(value)][0]
        current = self._assignment_identity_fields(value)
        if len(before) != len(current) or any(
            a is not b for a, b in zip(before, current, strict=True)
        ):
            raise DailyRuntimeRiskConflict("original admission preparation fields changed")

    def require_prepared_admission(self, value: PreparedDailyAdmission) -> None:
        """Authenticate the original complete preparation outside SQL."""
        self._require_prepared_admission(value)
        self.require_resolved_snapshot(value.snapshot)
        if self._admission_originals[id(value)][1] != content_digest(value.result):
            raise DailyRuntimeRiskConflict("original admission preparation contents changed")

    def require_prepared_admission_in_transaction(
        self, connection: Connection, value: PreparedDailyAdmission
    ) -> None:
        """Check original identities without decoding, hashing or private object I/O."""
        self._connection(connection)
        self._require_prepared_admission(value)

    def _require_prepared_assignment(self, value: PreparedDailyAssignment) -> None:
        self._require_owned(value)
        if type(value) is not PreparedDailyAssignment or value.seal is not self._seal:
            raise DailyRuntimeRiskConflict("original assignment preparation required")
        before = self._assignment_originals[id(value)][0]
        current = self._assignment_fields(value)
        if len(before) != len(current) or any(
            a is not b for a, b in zip(before, current, strict=True)
        ):
            raise DailyRuntimeRiskConflict("original assignment preparation fields changed")

    def require_prepared_assignment_in_transaction(
        self, connection: Connection, value: PreparedDailyAssignment
    ) -> None:
        """Compact original-value check; source authentication remains mandatory."""
        self._connection(connection)
        self._require_prepared_assignment(value)

    @staticmethod
    def _assignment_prefix_fields(value: RetainedDailyAssignmentPrefix) -> tuple[object, ...]:
        return SqlDailyRuntimeRisk._assignment_identity_fields(value)

    @staticmethod
    def _assignment_prefix_content(value: RetainedDailyAssignmentPrefix) -> str:
        return content_digest(
            (
                value.before_assignment,
                value.after_assignment,
                value.command,
                value.recorded_at,
                value.through_coordinator_sequence,
                value.commitment_ids,
                value.obligations,
                value.attempts,
                value.attempt_envelopes,
                value.observed_groups,
                value.control,
            )
        )

    def _require_assignment_prefix(self, value: RetainedDailyAssignmentPrefix) -> None:
        self._require_owned(value)
        if type(value) is not RetainedDailyAssignmentPrefix:
            raise DailyRuntimeRiskConflict("original assignment prefix required")
        before = self._assignment_prefix_originals[id(value)][0]
        current = self._assignment_prefix_fields(value)
        if len(before) != len(current) or any(
            a is not b for a, b in zip(before, current, strict=True)
        ):
            raise DailyRuntimeRiskConflict("original assignment prefix fields changed")

    def require_assignment_prefix(self, value: RetainedDailyAssignmentPrefix) -> None:
        """Authenticate owned immutable B query contents outside SQL."""
        self._require_assignment_prefix(value)
        if self._assignment_prefix_originals[id(value)][1] != self._assignment_prefix_content(
            value
        ):
            raise DailyRuntimeRiskConflict("original assignment prefix contents changed")

    @staticmethod
    def _observed_view_fields(value: RetainedDailyObservedHolds) -> tuple[object, ...]:
        objects: list[Any] = [
            value,
            value.result,
            value.result.before,
            value.result.after,
            value.inputs,
            value.inputs.source,
            value.inputs.previous,
            value.inputs.resulting,
            value.inputs.frontier,
            value.sources,
            value.sources.snapshot,
            value.sources.snapshot.plan,
        ]
        if value.result.group is not None:
            objects.extend(
                (
                    value.result.group,
                    value.result.group.source_ref,
                    value.result.group.source_ref.object_ref,
                )
            )
        for selected in value.selected:
            objects.extend((selected, selected.snapshot))
        for binding in (*value.result.before.bindings, *value.result.after.bindings):
            objects.extend((binding, binding.commitment))
        return tuple(getattr(obj, f.name) for obj in objects for f in fields(cast(Any, obj)))

    def _require_observed_group_view(self, value: RetainedDailyObservedHolds) -> None:
        self._require_owned(value)
        if type(value) is not RetainedDailyObservedHolds:
            raise DailyRuntimeRiskConflict("original retained observed inspection required")
        before, _ = self._observed_view_originals[id(value)]
        current = self._observed_view_fields(value)
        if len(before) != len(current) or any(
            a is not b for a, b in zip(before, current, strict=True)
        ):
            raise DailyRuntimeRiskConflict("original retained observed inspection fields changed")

    def require_observed_group_view(self, value: RetainedDailyObservedHolds) -> None:
        """Authenticate original owned contents outside SQL before composition."""
        self._require_observed_group_view(value)
        if value.inputs.semantic_sha256 != self._observed_view_originals[id(value)][1]:
            raise DailyRuntimeRiskConflict("original retained observed source contents changed")

    @staticmethod
    def _observed_fields(value: PreparedDailyObservedHolds) -> tuple[object, ...]:
        objects: list[Any] = [
            value,
            value.result,
            value.result.before,
            value.result.after,
            value.snapshot,
            value.snapshot.raw,
            *value.snapshot.raw.tables,
            *value.writes,
            *value.head_updates,
        ]
        if value.result.group is not None:
            objects.extend(
                (
                    value.result.group,
                    value.result.group.source_ref,
                    value.result.group.source_ref.object_ref,
                )
            )
        for binding in (*value.result.before.bindings, *value.result.after.bindings):
            objects.extend((binding, binding.commitment))
        sources = value.snapshot.observed_sources
        if sources is not None:
            objects.extend((sources, sources.snapshot, sources.snapshot.plan))
            for inputs in sources.inputs:
                objects.extend(
                    (inputs, inputs.source, inputs.previous, inputs.resulting, inputs.frontier)
                )
        return tuple(getattr(obj, f.name) for obj in objects for f in fields(cast(Any, obj)))

    @staticmethod
    def _observed_content_sha256(value: PreparedDailyObservedHolds) -> str:
        sources = value.snapshot.observed_sources
        return content_digest(
            (
                value.result,
                () if sources is None else sources.inputs,
            )
        )

    def _require_prepared_observed_holds(self, value: PreparedDailyObservedHolds) -> None:
        self._require_owned(value)
        if type(value) is not PreparedDailyObservedHolds:
            raise DailyRuntimeRiskConflict("original observed hold preparation required")
        before, current = self._observed_originals[id(value)], self._observed_fields(value)
        if len(before) != len(current) or any(
            a is not b for a, b in zip(before, current, strict=True)
        ):
            raise DailyRuntimeRiskConflict("original observed preparation fields changed")

    def require_prepared_observed_holds(self, value: PreparedDailyObservedHolds) -> None:
        """Authenticate the original complete source graph outside a SQL transaction."""
        self._require_prepared_observed_holds(value)
        if self._observed_contents[id(value)] != self._observed_content_sha256(value):
            raise DailyRuntimeRiskConflict("original observed preparation contents changed")

    def require_resolved_snapshot(self, value: ResolvedDailyRuntimeSnapshot) -> None:
        """Validate this store's exact detached snapshot without SQL or replay."""
        self._resolved(value)
        before = self._resolved_originals[id(value)]
        current = self._assignment_identity_fields(value)
        if len(before) != len(current) or any(
            a is not b for a, b in zip(before, current, strict=True)
        ):
            raise DailyRuntimeRiskConflict("original resolved daily snapshot fields changed")

    @staticmethod
    def _usage(budget: RuntimeReadBudget) -> tuple[int, int, int]:
        return budget.rows, budget.payload_bytes, budget.metadata_bytes

    @staticmethod
    def _raw_capture_fields(value: DailyRuntimeRawSnapshot) -> tuple[object, ...]:
        """Pin the small original capture/receipt boundary, without a graph walk."""
        if (
            type(value) is not DailyRuntimeRawSnapshot
            or type(value.receipt) is not AccountFenceReceipt
            or type(value.receipt.fence) is not AccountFence
        ):
            raise DailyRuntimeRiskConflict("exact original daily capture receipt required")
        return (
            *(getattr(value, item.name) for item in fields(DailyRuntimeRawSnapshot)),
            *(getattr(value.receipt, item.name) for item in fields(AccountFenceReceipt)),
            *(getattr(value.receipt.fence, item.name) for item in fields(AccountFence)),
        )

    def _require_original_capture(self, value: DailyRuntimeRawSnapshot) -> None:
        self._require_owned(value)
        current = self._raw_capture_fields(value)
        original = self._raw_capture_originals.get(id(value))
        if (
            value.seal is not self._seal
            or original is None
            or len(original) != len(current)
            or any(a is not b for a, b in zip(original, current, strict=True))
        ):
            raise DailyRuntimeRiskConflict("original daily capture fields changed")

    def require_same_complete_capture(
        self,
        original: ResolvedDailyRuntimeSnapshot,
        fresh: DailyRuntimeRawSnapshot,
    ) -> None:
        """Compare owned complete reads; this supplies no currentness or risk authority.

        The fixed factory scope retains its full original graph, object and final
        SQL/fence checks. This comparison never resolves or renews the old result.
        """
        self._resolved(original)
        self._require_original_capture(original.raw)
        self._require_original_capture(fresh)
        comparison = ContinuousCaptureComparison()
        expected_tables = (*DAILY_RUNTIME_TABLES, *CONTROL_TABLES)
        for raw in (original.raw, fresh):
            if (
                raw.command_id is not None
                or raw.input_refs is not None
                or raw.owner_command_ref is not None
                or type(raw.requested_envelopes) is not tuple
                or raw.requested_envelopes
                or type(raw.requested_preparations) is not tuple
                or raw.requested_preparations
                or raw.requested_observed_source is not None
                or type(raw.producer) is not RuntimeProducerRawSnapshot
                or type(raw.producer.tables) is not tuple
                or raw.producer.tables
                or type(raw.tables) is not tuple
                or len(raw.tables) != len(expected_tables)
                or any(
                    type(snapshot) is not RuntimeTableSnapshot
                    or snapshot.table is not table
                    or snapshot.account_id != raw.account_id
                    for snapshot, table in zip(raw.tables, expected_tables, strict=True)
                )
            ):
                raise DailyRuntimeRiskConflict("complete factory daily read required")
            self._continued_budget(raw)
        comparison.data(original.raw.account_id, fresh.account_id)
        comparison.data(original.raw.capture_usage, fresh.capture_usage)
        before, after = original.raw.receipt, fresh.receipt
        comparison.data(
            tuple(getattr(before.fence, item.name) for item in fields(AccountFence)),
            tuple(getattr(after.fence, item.name) for item in fields(AccountFence)),
        )
        comparison.data(
            (before.valid_until, before.policy_sha256, before.lease_sha256),
            (after.valid_until, after.policy_sha256, after.lease_sha256),
        )
        if (
            type(before.validated_at) is not datetime
            or type(after.validated_at) is not datetime
            or before.fence.account_id != original.raw.account_id
            or after.fence.account_id != fresh.account_id
            or not before.validated_at <= after.validated_at < before.valid_until
        ):
            raise DailyRuntimeRiskConflict("original complete capture receipt differs")
        _require_same_runtime_tables(original.raw.tables, fresh.tables, comparison=comparison)
        old_attempt = original.attempt_sources
        if old_attempt is None:
            if original.raw.attempt_sources is not None or fresh.attempt_sources is not None:
                raise DailyRuntimeRiskConflict("complete attempt capture inventory differs")
        else:
            if (
                old_attempt.snapshot is not original.raw.attempt_sources
                or fresh.attempt_sources is None
            ):
                raise DailyRuntimeRiskConflict("complete attempt capture inventory differs")
            reader = self._attempt_reader()
            if not callable(getattr(reader, "require_same_attempt_capture", None)):
                raise DailyRuntimeRiskConflict("actual attempt capture comparator required")
            reader.require_same_attempt_capture(
                old_attempt, fresh.attempt_sources, comparison=comparison
            )
        old_observed = original.observed_sources
        if old_observed is None:
            if original.raw.observed_sources is not None or fresh.observed_sources is not None:
                raise DailyRuntimeRiskConflict("complete observed capture inventory differs")
        else:
            if (
                old_observed.snapshot is not original.raw.observed_sources
                or fresh.observed_sources is None
            ):
                raise DailyRuntimeRiskConflict("complete observed capture inventory differs")
            observed_reader = self._observed_reader()
            if not callable(getattr(observed_reader, "require_same_observed_capture", None)):
                raise DailyRuntimeRiskConflict("actual observed capture comparator required")
            observed_reader.require_same_observed_capture(
                old_observed, fresh.observed_sources, comparison=comparison
            )
        self._resolved(original)
        self._require_original_capture(original.raw)
        self._require_original_capture(fresh)

    def _continued_budget(self, raw: DailyRuntimeRawSnapshot) -> RuntimeReadBudget:
        self._require_owned(raw)
        rows, payload, metadata = raw.capture_usage
        if any(type(value) is not int or value < 0 for value in raw.capture_usage):
            raise DailyRuntimeRiskConflict("invalid retained capture usage")
        budget = RuntimeReadBudget(payload_bytes=payload, metadata_bytes=metadata, rows=rows)
        budget.charge(0, 0, 0)
        return budget

    @staticmethod
    def _row_sizes(table: sa.Table, row: Mapping[str, Any]) -> tuple[int, int]:
        payload = metadata = 0
        for column in table.c:
            value = row[column.name]
            _kind, limit, large = _field(column)
            size = (
                0
                if value is None
                else len(value if isinstance(value, bytes) else str(value).encode("utf-8"))
            )
            if size > limit:
                raise DailyRuntimeRiskConflict("prepared retained field exceeds profile")
            if large:
                payload += size
            else:
                metadata += size
        return payload, metadata

    def _check_result_bound(
        self,
        prepared: PreparedDailyAdmission
        | PreparedDailyAssignment
        | PreparedDailyAttemptMutation
        | PreparedDailyObservedHolds,
    ) -> None:
        # Reject a write which would create a footprint the frozen profile cannot read.
        raw = prepared.snapshot.raw
        sources = (
            *(() if raw.attempt_sources is None else raw.attempt_sources.tables),
            *(() if raw.observed_sources is None else raw.observed_sources.tables),
        )
        rows = {
            item.table: list(item.rows) for item in (*raw.tables, *raw.producer.tables, *sources)
        }
        budget = self._continued_budget(raw)
        for write in prepared.writes:
            rows[write.table].append(write.values)
            budget.charge(1, *self._row_sizes(write.table, write.values))
        updates = (
            list(prepared.head_updates)
            if isinstance(prepared, (PreparedDailyAttemptMutation, PreparedDailyObservedHolds))
            else []
        )
        if isinstance(prepared, PreparedDailyAssignment):
            updates.append(
                _HeadUpdate(
                    assignment_heads,
                    rows[assignment_heads][0] if rows[assignment_heads] else None,
                    prepared.head_values,
                )
            )
        for update in updates:
            before = next(
                (
                    row
                    for row in rows[update.table]
                    if all(
                        row[column.name] == update.values[column.name]
                        for column in update.table.primary_key.columns
                    )
                ),
                None,
            )
            if before is not None:
                rows[update.table].remove(before)
            rows[update.table].append(update.values)
            new_payload, new_metadata = self._row_sizes(update.table, update.values)
            old_payload, old_metadata = (
                (0, 0) if before is None else self._row_sizes(update.table, before)
            )
            budget.charge(
                int(before is None),
                max(0, new_payload - old_payload),
                max(0, new_metadata - old_metadata),
            )
        if any(len(values) > MAX_ROWS for values in rows.values()):
            raise DailyRuntimeRiskConflict("prepared daily table row bound exceeded")

    def _require_owned(self, value: object) -> None:
        if self._owned.get(id(value)) is not value:
            raise DailyRuntimeRiskConflict("exact original store-produced object required")
        if (
            isinstance(value, DailyRuntimeRawSnapshot)
            and value.capture_usage is not self._capture_usage[id(value)]
        ):
            raise DailyRuntimeRiskConflict("original captured aggregate usage changed")

    def _connection(self, connection: Connection) -> None:
        if connection.engine is not self.engine or not connection.in_transaction():
            raise DailyRuntimeRiskConflict("same-engine active caller transaction required")
        if (
            connection.dialect.name == "sqlite"
            and getattr(connection.connection.driver_connection, "in_transaction", False)
            is not True
        ):
            raise DailyRuntimeRiskConflict("SQLite requires an explicit outer BEGIN")
        if connection.dialect.name == "postgresql" and connection.get_isolation_level() not in (
            "REPEATABLE READ",
            "SERIALIZABLE",
        ):
            raise DailyRuntimeRiskConflict("daily risk requires a repeatable transaction")
        if connection.dialect.name not in ("sqlite", "postgresql"):
            raise DailyRuntimeRiskConflict("unsupported daily risk database dialect")

    def _read_snapshot(
        self,
        *,
        account_id: str,
        fence: AccountFence,
        command_id: str | None = None,
        input_refs: RuntimeRiskInputRefs | None = None,
        owner_command_ref: JournalReceipt | None = None,
    ) -> DailyRuntimeRawSnapshot:
        require_identifier(account_id, "account")
        if type(fence) is not AccountFence or fence.account_id != account_id:
            raise DailyRuntimeRiskConflict("account and fence differ")
        if input_refs is not None and owner_command_ref is not None:
            raise DailyRuntimeRiskConflict("snapshot requires one mutation scope")
        if command_id is not None:
            require_identifier(command_id, "command")
        receipt = self.coordinator.revalidate(fence)
        budget = RuntimeReadBudget()
        with _repeatable_read_transaction(self.engine) as connection:
            self._connection(connection)
            self._no_legacy(connection, account_id)
            tables = tuple(
                capture_runtime_table(connection, table, account_id=account_id, budget=budget)
                for table in (*DAILY_RUNTIME_TABLES, *CONTROL_TABLES)
            )
            # A retained command is resolved without fresh producer reconstruction.
            prior = next(
                (
                    row
                    for item in tables
                    if item.table is admissions
                    for row in item.rows
                    if row["command_id"] == command_id
                ),
                None,
            )
            producer = (
                RuntimeProducerRawSnapshot(())
                if prior is not None or (input_refs is None and owner_command_ref is None)
                else self.producers.capture_in_transaction(
                    connection,
                    account_id=account_id,
                    refs=input_refs,
                    owner_command_ref=owner_command_ref,
                    budget=budget,
                )
            )
            if (
                type(producer) is not RuntimeProducerRawSnapshot
                or type(producer.tables) is not tuple
            ):
                raise DailyRuntimeRiskConflict("exact bounded producer snapshot required")
            footprint = (*tables, *producer.tables)
            if len(budget.captured) != len(footprint) or any(
                captured is not declared
                for captured, declared in zip(budget.captured, footprint, strict=True)
            ):
                raise DailyRuntimeRiskConflict("producer bypassed shared bounded capture")
            if (
                prior is None
                and (input_refs is not None or owner_command_ref is not None)
                and not any(item.rows for item in producer.tables)
            ):
                raise DailyRuntimeRiskConflict("positive mutation requires retained producer rows")
            identities = [item.table.name for item in (*tables, *producer.tables)]
            if len(identities) != len(set(identities)) or any(
                type(item) is not RuntimeTableSnapshot or item.account_id != account_id
                for item in producer.tables
            ):
                raise DailyRuntimeRiskConflict("producer snapshot footprint conflicts")
        return self._own(
            DailyRuntimeRawSnapshot(
                account_id,
                receipt,
                tables,
                producer,
                command_id,
                input_refs,
                owner_command_ref,
                self._seal,
                capture_usage=self._usage(budget),
            )
        )

    def read_snapshot(
        self,
        *,
        account_id: str,
        fence: AccountFence,
        command_id: str | None = None,
        input_refs: RuntimeRiskInputRefs | None = None,
        owner_command_ref: JournalReceipt | None = None,
    ) -> DailyRuntimeRawSnapshot:
        raw = self._read_snapshot(
            account_id=account_id,
            fence=fence,
            command_id=command_id,
            input_refs=input_refs,
            owner_command_ref=owner_command_ref,
        )
        return self._capture_observed_sources(self._capture_attempt_sources(raw, (), ()), None)

    def read_attempt_snapshot(
        self,
        *,
        account_id: str,
        fence: AccountFence,
        envelopes: tuple[DailyAttemptEnvelope, ...],
        preparations: tuple[DailyAttemptPreparation, ...] = (),
    ) -> DailyRuntimeRawSnapshot:
        if (
            type(envelopes) is not tuple
            or not 1 <= len(envelopes) <= 4
            or any(
                type(item) is not DailyAttemptEnvelope or item.account_id != account_id
                for item in envelopes
            )
            or type(preparations) is not tuple
            or len(preparations) > 4
            or any(type(item) is not DailyAttemptPreparation for item in preparations)
        ):
            raise DailyRuntimeRiskConflict(
                "attempt mutation requires an exact bounded account group"
            )
        group = {
            (item.coordinator_command_id, item.coordinator_sequence, item.source_ref)
            for item in envelopes
        }
        if len(group) != 1 or len({item.event.attempt_id for item in envelopes}) != len(envelopes):
            raise DailyRuntimeRiskConflict("attempt command group differs or repeats an attempt")
        raw = self._read_snapshot(account_id=account_id, fence=fence)
        return self._capture_observed_sources(
            self._capture_attempt_sources(raw, envelopes, preparations), None
        )

    def read_observed_hold_snapshot(
        self,
        *,
        account_id: str,
        fence: AccountFence,
        source_ref: ContinuousEvidenceRef,
    ) -> DailyRuntimeRawSnapshot:
        if (
            type(source_ref) is not ContinuousEvidenceRef
            or source_ref.schema_id != "daily-observed-hold-source/1"
        ):
            raise DailyRuntimeRiskConflict("exact observed hold source reference required")
        raw = self._read_snapshot(account_id=account_id, fence=fence)
        return self._capture_observed_sources(
            self._capture_attempt_sources(raw, (), ()), source_ref
        )

    def _observed_reader(self) -> RuntimeObservedHoldProducerReader:
        names = (
            "prepare_observed_hold_source_read",
            "capture_observed_hold_sources_in_transaction",
            "resolve_observed_hold_sources",
            "recheck_observed_hold_sources_in_transaction",
        )
        if any(not callable(getattr(self.producers, name, None)) for name in names):
            raise DailyRuntimeRiskConflict(
                "observed holds require their actual retained-source producer"
            )
        return cast(RuntimeObservedHoldProducerReader, self.producers)

    def _capture_observed_sources(
        self,
        raw: DailyRuntimeRawSnapshot,
        requested: ContinuousEvidenceRef | None,
    ) -> DailyRuntimeRawSnapshot:
        stored = tuple(
            self._decode(row, DailyObservedHoldGroup)
            for table in raw.tables
            if table.table is observed_hold_groups
            for row in _typed_rows(table)
        )
        if not stored and requested is None:
            return raw
        references = tuple(
            sorted(
                {
                    *(item.source_ref for item in stored),
                    *((requested,) if requested is not None else ()),
                },
                key=lambda ref: (ref.semantic_sha256, ref.object_ref.object_sha256),
            )
        )
        reader = self._observed_reader()
        plan = reader.prepare_observed_hold_source_read(references)
        if type(plan) is not RuntimeObservedHoldSourcePlan or plan.references != references:
            raise DailyRuntimeRiskConflict(
                "observed source plan differs from exact retained references"
            )
        old = (
            *raw.tables,
            *raw.producer.tables,
            *(() if raw.attempt_sources is None else raw.attempt_sources.tables),
        )
        budget = self._continued_budget(raw)
        budget.captured.extend(old)
        initial_count = len(budget.captured)
        with _repeatable_read_transaction(self.engine) as connection:
            self._connection(connection)
            self._no_legacy(connection, raw.account_id)
            for table in old:
                _recheck_table(connection, table)
            captured = reader.capture_observed_hold_sources_in_transaction(
                connection, plan, account_id=raw.account_id, budget=budget
            )
            if (
                type(captured) is not RuntimeObservedHoldSourceSnapshot
                or captured.plan is not plan
                or not (
                    any(table.rows for table in captured.tables)
                    or any(
                        table.table is continuous_account_commits and table.rows for table in old
                    )
                )
                or len(budget.captured) - initial_count != len(captured.tables)
                or any(
                    a is not b
                    for a, b in zip(budget.captured[initial_count:], captured.tables, strict=True)
                )
                or any(table.account_id != raw.account_id for table in captured.tables)
            ):
                raise DailyRuntimeRiskConflict(
                    "observed producer bypassed complete bounded source capture"
                )
        return self._own(
            replace(
                raw,
                observed_sources=captured,
                requested_observed_source=requested,
                capture_usage=self._usage(budget),
            )
        )

    def _attempt_reader(self) -> RuntimeAttemptProducerReader:
        names = (
            "prepare_attempt_source_read",
            "capture_attempt_sources_in_transaction",
            "resolve_attempt_sources",
            "recheck_attempt_sources_in_transaction",
        )
        if any(not callable(getattr(self.producers, name, None)) for name in names):
            raise DailyRuntimeRiskConflict(
                "daily lifecycle requires its concrete retained-source producer"
            )
        return cast(RuntimeAttemptProducerReader, self.producers)

    def _capture_attempt_sources(
        self,
        raw: DailyRuntimeRawSnapshot,
        requested: tuple[DailyAttemptEnvelope, ...],
        preparations: tuple[DailyAttemptPreparation, ...],
    ) -> DailyRuntimeRawSnapshot:
        # Discover typed envelopes and source plans only after the first SQL snapshot closes.
        stored = tuple(
            self._decode(row, DailyAttemptEnvelope)
            for table in raw.tables
            if table.table is attempt_events
            for row in _typed_rows(table)
        )
        if not stored and not requested:
            return raw
        references = tuple(
            sorted(
                {item.source_ref for item in (*stored, *requested)},
                key=lambda ref: (ref.semantic_sha256, ref.object_ref.object_sha256),
            )
        )
        reader = self._attempt_reader()
        plan = reader.prepare_attempt_source_read(references)
        if type(plan) is not RuntimeAttemptSourcePlan or plan.references != references:
            raise DailyRuntimeRiskConflict(
                "attempt producer plan differs from exact source references"
            )
        budget = self._continued_budget(raw)
        budget.captured.extend((*raw.tables, *raw.producer.tables))
        initial_count = len(budget.captured)
        with _repeatable_read_transaction(self.engine) as connection:
            self._connection(connection)
            self._no_legacy(connection, raw.account_id)
            for captured in (*raw.tables, *raw.producer.tables):
                _recheck_table(connection, captured)
            captured_sources = reader.capture_attempt_sources_in_transaction(
                connection, plan, account_id=raw.account_id, budget=budget
            )
            if (
                type(captured_sources) is not RuntimeAttemptSourceSnapshot
                or captured_sources.plan is not plan
                or not (
                    any(table.rows for table in captured_sources.tables)
                    or any(
                        item.table is continuous_account_commits and item.rows
                        for item in (*raw.tables, *raw.producer.tables)
                    )
                )
                or len(budget.captured) - initial_count != len(captured_sources.tables)
                or any(
                    a is not b
                    for a, b in zip(
                        budget.captured[initial_count:], captured_sources.tables, strict=True
                    )
                )
                or any(table.account_id != raw.account_id for table in captured_sources.tables)
            ):
                raise DailyRuntimeRiskConflict(
                    "attempt producer bypassed its complete bounded source capture"
                )
        return self._own(
            replace(
                raw,
                attempt_sources=captured_sources,
                requested_envelopes=requested,
                requested_preparations=preparations,
                capture_usage=self._usage(budget),
            )
        )

    @staticmethod
    def _no_legacy(connection: Connection, account_id: str) -> None:
        if connection.scalar(
            sa.select(
                sa.exists(
                    sa.select(phase2_batch_reservations.c.reservation_id).where(
                        phase2_batch_reservations.c.account_id == account_id
                    )
                )
            )
        ):
            raise DailyRuntimeRiskConflict(
                SQL_PROFILE + ": any legacy reservation history requires reviewed bridge"
            )

    def resolve_snapshot(self, raw: DailyRuntimeRawSnapshot) -> ResolvedDailyRuntimeSnapshot:
        self._require_owned(raw)
        if type(raw) is not DailyRuntimeRawSnapshot or raw.seal is not self._seal:
            raise DailyRuntimeRiskConflict("snapshot belongs to another store")
        rows = {item.table.name: _typed_rows(item) for item in raw.tables}
        chain = []
        previous = None
        binding = None
        for generation, row in enumerate(rows[assignments.name], 1):
            value = self._decode(row, RuntimeRiskAssignment)
            if (value.account_id, value.generation, value.previous_assignment_sha256) != (
                raw.account_id,
                generation,
                previous,
            ) or (row["account_id"], row["generation"], row["previous_sha256"]) != (
                raw.account_id,
                generation,
                previous,
            ):
                raise DailyRuntimeRiskConflict("assignment chain binding differs")
            command = self.codec.decode_record(row["command_payload"], RuntimeAssignmentCommand)
            if self.codec.encode_record(command) != row["command_payload"] or (
                command.command_id,
                command.semantic_sha256,
                command.account_id,
                command.before_assignment_sha256,
                command.after_assignment_sha256,
            ) != (
                row["command_id"],
                row["command_sha256"],
                raw.account_id,
                previous,
                value.semantic_sha256,
            ):
                raise DailyRuntimeRiskConflict("retained owner command binding differs")
            if not command.requested_at <= row["recorded_at"] < command.expires_at:
                raise DailyRuntimeRiskConflict("assignment recording falls outside owner validity")
            if generation == 1 and value.enabled_for_new_exposure:
                raise DailyRuntimeRiskConflict("initial assignment was not disabled")
            if binding is not None and value.account_binding_sha256 != binding:
                raise DailyRuntimeRiskConflict("assignment history replaced account identity")
            previous, binding = value.semantic_sha256, value.account_binding_sha256
            chain.append(value)
        heads = rows[assignment_heads.name]
        if (not chain and heads) or (
            chain
            and (
                len(heads) != 1
                or dict(heads[0])
                != dict(account_id=raw.account_id, generation=len(chain), semantic_sha256=previous)
            )
        ):
            raise DailyRuntimeRiskConflict("assignment chain/head differs")
        control_heads = rows[phase5_operational_control_heads.name]
        if len(control_heads) > 1:
            raise DailyRuntimeRiskConflict("duplicate control head")
        control = resolve_operational_control_rows(
            account_id=raw.account_id,
            transition_rows=tuple(
                sorted(
                    rows[phase5_operational_control_transitions.name],
                    key=lambda row: cast(int, row["sequence_number"]),
                )
            ),
            completion_rows=rows[phase5_operational_control_completions.name],
            head_row=None if not control_heads else control_heads[0],
        )
        records = []
        expected_holds: list[Mapping[str, Any]] = []
        expected_heads: list[Mapping[str, Any]] = []
        expected_outbound: list[Mapping[str, Any]] = []
        for row in rows[admissions.name]:
            record = self._decode(row, _AdmissionRecord)
            admission, resolved = record.admission, record.resolved
            assignment = admission.evidence.assignment
            identifier = content_digest(("daily-admission/1", raw.account_id, record.command_id))
            if (
                row["admission_id"],
                row["account_id"],
                row["command_id"],
                row["request_sha256"],
                row["batch_sha256"],
                row["assignment_generation"],
                row["assignment_sha256"],
                row["approved"],
            ) != (
                identifier,
                raw.account_id,
                record.command_id,
                record.request_sha256,
                admission.decision.batch.semantic_sha256,
                assignment.generation,
                assignment.semantic_sha256,
                admission.decision.approved,
            ):
                raise DailyRuntimeRiskConflict("admission row binding differs")
            if (
                not 1 <= assignment.generation <= len(chain)
                or chain[assignment.generation - 1] != assignment
            ):
                raise DailyRuntimeRiskConflict("admission assignment history differs")
            decision = evaluate_daily_risk(
                assignment.policy,
                resolved.snapshot,
                admission.decision.batch,
                admission.evidence,
                admission.evidence.produced_at,
            )
            if (
                decision != admission.decision
                or resolved.inputs != admission.evidence.inputs
                or resolved.producer_map != admission.evidence.producer_map
            ):
                raise DailyRuntimeRiskConflict("admission risk replay differs")
            expected = (
                self._prepare(resolved, decision.batch, decision, assignment.policy)
                if decision.approved
                else ()
            )
            if expected != record.prepared_commitments:
                raise DailyRuntimeRiskConflict("admission canonical install differs")
            writes = self._hold_writes(record)
            expected_holds.extend(w.values for w in writes if w.table is hold_events)
            expected_heads.extend(w.values for w in writes if w.table is hold_heads)
            expected_outbound.extend(w.values for w in writes if w.table is outbound)
            records.append(record)
        attempts, envelopes, sources, later_holds, latest_heads, observed, observed_sources = (
            self._resolve_attempt_history(
                raw,
                tuple(records),
                rows,
                expected_holds,
                expected_heads,
            )
        )
        expected_holds.extend(later_holds)
        if attempts or observed:
            expected_heads = latest_heads
        for table, expected_rows in (
            (hold_events, expected_holds),
            (hold_heads, expected_heads),
            (outbound, expected_outbound),
        ):
            current = sorted(rows[table.name], key=lambda row: row["hold_id"])
            expected_rows = sorted(expected_rows, key=lambda row: row["hold_id"])
            if current != expected_rows:
                raise DailyRuntimeRiskConflict(
                    "admission hold/outbound inventory or binding differs"
                )
        latest_by_id = {row["hold_id"]: row for row in expected_heads}
        bindings = tuple(
            sorted(
                (
                    self._decode(row, RuntimeCommitmentBinding)
                    for row in expected_holds
                    if row["revision"] == latest_by_id[row["hold_id"]]["revision"]
                ),
                key=lambda binding: binding.commitment.commitment_id,
            )
        )
        obligations = RuntimeObligationInventory(
            bindings=bindings,
            legacy_universe_sha256=content_digest(()),
            daily_universe_sha256=content_digest(bindings),
        )
        return self._own(
            ResolvedDailyRuntimeSnapshot(
                raw,
                None if not chain else chain[-1],
                tuple(chain),
                tuple(records),
                obligations,
                control,
                self._seal,
                attempts,
                envelopes,
                sources,
                observed,
                observed_sources,
            )
        )

    def _consumption_write(
        self,
        preparation: DailyAttemptPreparation,
        records: tuple[_AdmissionRecord, ...],
    ) -> _Write:
        matches = [
            record for record in records if record.admission == preparation.original_admission
        ]
        if len(matches) != 1:
            raise DailyRuntimeRiskConflict("attempt lost its exact original admission")
        record = matches[0]
        if preparation.original_hold not in self._bindings(record):
            raise DailyRuntimeRiskConflict("attempt changed original hold producer lineage")
        encoded = self._encode(record)
        if (
            preparation.admission_source.semantic_sha256_ref != record.semantic_sha256
            or preparation.admission_source.object_ref.object_sha256 != encoded["payload_sha256"]
            or preparation.admission_source.object_ref.byte_count
            != len(cast(bytes, encoded["payload"]))
        ):
            raise DailyRuntimeRiskConflict(
                "attempt admission object differs from enclosing SQL record"
            )
        item = preparation.original_hold.commitment
        return _Write(
            consumptions,
            MappingProxyType(
                dict(
                    admission_id=content_digest(
                        (
                            "daily-admission/1",
                            preparation.request.source_account_id,
                            record.command_id,
                        )
                    ),
                    intent_id=item.intent_id,
                    account_id=preparation.request.source_account_id,
                    hold_id=item.commitment_id,
                    attempt_id=preparation.attempt_id,
                    **self._encode(preparation),
                )
            ),
        )

    def _event_write(
        self, envelope: DailyAttemptEnvelope, consumption: Mapping[str, Any]
    ) -> _Write:
        event = envelope.event
        if (envelope.account_id, event.attempt_id) != (
            consumption["account_id"],
            consumption["attempt_id"],
        ):
            raise DailyRuntimeRiskConflict("event account/consumption identity differs")
        return _Write(
            attempt_events,
            MappingProxyType(
                dict(
                    account_id=envelope.account_id,
                    attempt_id=event.attempt_id,
                    sequence=event.sequence,
                    event_id=event.event_id,
                    event_sha256=event.semantic_sha256,
                    previous_event_sha256=event.previous_event_sha256,
                    state=event.state.value,
                    recorded_at=event.recorded_at,
                    admission_id=consumption["admission_id"],
                    intent_id=consumption["intent_id"],
                    hold_id=consumption["hold_id"],
                    coordinator_command_id=envelope.coordinator_command_id,
                    coordinator_sequence=envelope.coordinator_sequence,
                    **self._encode(envelope),
                )
            ),
        )

    @staticmethod
    def _attempt_head(attempt: CanonicalDailyAttempt) -> Mapping[str, Any]:
        return MappingProxyType(
            dict(
                account_id=attempt.preparation.request.source_account_id,
                attempt_id=attempt.attempt_id,
                sequence=len(attempt.events),
                event_sha256=attempt.events[-1].semantic_sha256,
                attempt_sha256=attempt.semantic_sha256,
                state=attempt.state.value,
            )
        )

    @staticmethod
    def _inventory(bindings: Mapping[str, RuntimeCommitmentBinding]) -> RuntimeObligationInventory:
        values = tuple(bindings[key] for key in sorted(bindings))
        return RuntimeObligationInventory(
            bindings=values,
            legacy_universe_sha256=content_digest(()),
            daily_universe_sha256=content_digest(values),
        )

    def _resolved_attempt_sources(
        self,
        raw: DailyRuntimeRawSnapshot,
        records: tuple[_AdmissionRecord, ...],
    ) -> ResolvedRuntimeAttemptSources | None:
        if raw.attempt_sources is None:
            return None
        admission_rows = next(table for table in raw.tables if table.table is admissions)
        views = tuple(self._admission_view(row) for row in _typed_rows(admission_rows))
        result = self._attempt_reader().resolve_attempt_sources(
            raw.attempt_sources, admissions=views
        )
        if (
            type(result) is not ResolvedRuntimeAttemptSources
            or result.snapshot is not raw.attempt_sources
            or len(result.sources) != len(raw.attempt_sources.plan.references)
        ):
            raise DailyRuntimeRiskConflict("attempt source resolution inventory differs")
        for reference, source in zip(
            raw.attempt_sources.plan.references, result.sources, strict=True
        ):
            if (
                type(source) is not RuntimeAttemptAccountingSource
                or source.account_id != raw.account_id
            ):
                raise DailyRuntimeRiskConflict("attempt source account/type differs")
            payload = self.codec.encode_record(source)
            if (
                source.semantic_sha256 != reference.semantic_sha256
                or len(payload) != reference.object_ref.byte_count
                or hashlib.sha256(payload).hexdigest() != reference.object_ref.object_sha256
            ):
                raise DailyRuntimeRiskConflict("attempt source canonical object identity differs")
        return result

    def _source_object(self, reference: ContinuousEvidenceRef, value: ContractRecord) -> None:
        payload = self.codec.encode_record(value)
        if (
            reference.semantic_sha256 != value.semantic_sha256
            or reference.object_ref.byte_count != len(payload)
            or reference.object_ref.object_sha256 != hashlib.sha256(payload).hexdigest()
        ):
            raise DailyRuntimeRiskConflict("observed source canonical object binding differs")

    def _resolved_observed_sources(
        self,
        raw: DailyRuntimeRawSnapshot,
    ) -> ResolvedRuntimeObservedHoldSources | None:
        if raw.observed_sources is None:
            return None
        views = tuple(
            self._admission_view(row)
            for table in raw.tables
            if table.table is admissions
            for row in _typed_rows(table)
        )
        result = self._observed_reader().resolve_observed_hold_sources(
            raw.observed_sources, admissions=views
        )
        if (
            type(result) is not ResolvedRuntimeObservedHoldSources
            or result.snapshot is not raw.observed_sources
            or len(result.inputs) != len(raw.observed_sources.plan.references)
        ):
            raise DailyRuntimeRiskConflict("observed source resolution inventory differs")
        for reference, inputs in zip(
            raw.observed_sources.plan.references, result.inputs, strict=True
        ):
            if (
                type(inputs) is not RuntimeObservedHoldInputs
                or inputs.source.scope.account_id != raw.account_id
            ):
                raise DailyRuntimeRiskConflict("observed source type/account differs")
            source, previous, current = inputs.source, inputs.previous, inputs.resulting
            self._source_object(reference, source)
            for ref, value in (
                (source.previous_checkpoint, previous),
                (source.resulting_checkpoint, current),
                (source.frontier, inputs.frontier),
            ):
                self._source_object(ref, value)
            if len(source.application_batches) != len(inputs.application_batches):
                raise DailyRuntimeRiskConflict("observed application batch inventory differs")
            for ref, batch in zip(
                source.application_batches, inputs.application_batches, strict=True
            ):
                self._source_object(ref, batch)
            if (
                type(previous.inputs) is not ContinuousEngineInputs
                or current.inputs != previous.inputs
                or previous.inputs.spec.account_id != source.scope.account_id
                or previous.inputs.spec.account_binding_sha256
                != source.scope.account_binding_sha256
                or previous.inputs.spec.execution_policy != source.execution_policy
                or current.now != source.applied_at
                or inputs.frontier.previous_checkpoint_sha256 != previous.semantic_sha256
                or inputs.frontier.source_frontier_sha256 != source.source_closure_sha256
                or inputs.frontier.knowledge_at != current.now
                or current.runtime_decisions != previous.runtime_decisions
                or current.state.submissions != previous.state.submissions
                or current.request_rows != previous.request_rows
                or not inputs.frontier.events
                or any(
                    type(event.payload) is not ContinuousReconciliationBatch
                    for event in inputs.frontier.events
                )
                or any(
                    isinstance(event.payload, ContinuousReconciliationBatch)
                    and event.payload.scope.account_id != source.scope.account_id
                    for event in inputs.frontier.events
                )
                or not inputs.application_batches
                or inputs.application_batches[-1].state.commitments != current.state.commitments
            ):
                raise DailyRuntimeRiskConflict(
                    "observed frontier/engine policy or canonical state differs"
                )
            if (
                previous.current.snapshot.journal_sha256,
                previous.current.snapshot.order_sha256,
            ) != (source.heads.ledger_sha256, source.heads.order_sha256):
                raise DailyRuntimeRiskConflict("observed original financial heads differ")
        return result

    def _observed_write(self, group: DailyObservedHoldGroup) -> _Write:
        return _Write(
            observed_hold_groups,
            MappingProxyType(
                dict(
                    account_id=group.account_id,
                    coordinator_sequence=group.coordinator_sequence,
                    coordinator_command_id=group.coordinator_command_id,
                    source_sha256=group.source_ref.semantic_sha256,
                    before_inventory_sha256=group.before_inventory_sha256,
                    after_inventory_sha256=group.after_inventory_sha256,
                    applied_at=group.applied_at,
                    **self._encode(group),
                )
            ),
        )

    def _apply_observed_source(
        self,
        inputs: RuntimeObservedHoldInputs,
        reference: ContinuousEvidenceRef,
        bindings: Mapping[str, RuntimeCommitmentBinding],
    ) -> tuple[DailyObservedHoldResult, dict[str, RuntimeCommitmentBinding]]:
        source = inputs.source
        before_items = {item.commitment_id: item for item in inputs.previous.state.commitments}
        after_items = {item.commitment_id: item for item in inputs.resulting.state.commitments}
        if before_items.keys() != after_items.keys() or any(
            key not in bindings or bindings[key].commitment != item
            for key, item in before_items.items()
        ):
            raise DailyRuntimeRiskConflict("observed original canonical hold inventory differs")
        before = self._inventory({key: bindings[key] for key in before_items})
        if before.semantic_sha256 != source.heads.capacity_sha256:
            raise DailyRuntimeRiskConflict("observed original capacity head differs")
        changed = tuple(
            replace(bindings[key], commitment=after_items[key])
            for key in sorted(before_items)
            if before_items[key] != after_items[key]
        )
        updated = dict(bindings)
        updated.update({item.commitment.commitment_id: item for item in changed})
        after = self._inventory({key: updated[key] for key in before_items})
        group = (
            None
            if not changed
            else DailyObservedHoldGroup(
                account_id=source.scope.account_id,
                coordinator_command_id=source.coordinator_command_id,
                coordinator_sequence=source.coordinator_sequence,
                source_ref=reference,
                before_inventory_sha256=before.semantic_sha256,
                after_inventory_sha256=after.semantic_sha256,
                changed_hold_ids=tuple(item.commitment.commitment_id for item in changed),
                applied_at=source.applied_at,
            )
        )
        return DailyObservedHoldResult(
            source.coordinator_command_id,
            source.coordinator_sequence,
            before,
            after,
            changed,
            inputs.resulting.state.semantic_sha256,
            group,
        ), updated

    def _apply_attempt_group(
        self,
        *,
        envelopes: tuple[DailyAttemptEnvelope, ...],
        source: RuntimeAttemptAccountingSource,
        preparations: Mapping[str, DailyAttemptPreparation],
        current_attempts: Mapping[str, CanonicalDailyAttempt],
        known_bindings: Mapping[str, RuntimeCommitmentBinding],
    ) -> tuple[
        dict[str, CanonicalDailyAttempt], dict[str, RuntimeCommitmentBinding], AccountingState
    ]:
        group = {
            (
                item.account_id,
                item.coordinator_command_id,
                item.coordinator_sequence,
                item.source_ref.semantic_sha256,
            )
            for item in envelopes
        }
        if (
            not 1 <= len(envelopes) <= 4
            or len(group) != 1
            or next(iter(group))
            != (
                source.account_id,
                source.coordinator_command_id,
                source.coordinator_sequence,
                source.semantic_sha256,
            )
            or len({item.event.attempt_id for item in envelopes}) != len(envelopes)
            or any(item.event.recorded_at != source.checked_at for item in envelopes)
            or source.heads.attempt_sha256
            != daily_attempt_inventory_sha256(tuple(current_attempts.values()))
        ):
            raise DailyRuntimeRiskConflict("attempt group source/head/order binding differs")
        # The concrete producer authenticates the original complete checkpoint inventory.
        # Every binding in that inventory must also match its explained retained SQL lineage.
        for binding in source.obligations.bindings:
            if known_bindings.get(binding.commitment.commitment_id) != binding:
                raise DailyRuntimeRiskConflict("attempt source hold has no exact prior SQL lineage")
        if tuple(sorted(source.state.commitments, key=lambda item: item.commitment_id)) != tuple(
            binding.commitment for binding in source.obligations.bindings
        ):
            raise DailyRuntimeRiskConflict("attempt source canonical state/hold inventory differs")
        projection = self.accounting.project(
            state=source.state, context=source.context, policy=source.execution_policy
        )
        if (projection.snapshot.journal_sha256, projection.snapshot.order_sha256) != (
            source.heads.ledger_sha256,
            source.heads.order_sha256,
        ):
            raise DailyRuntimeRiskConflict("attempt source canonical ledger/order heads differ")
        attempts = dict(current_attempts)
        for envelope in envelopes:
            event = envelope.event
            if event.attempt_id not in preparations:
                raise DailyRuntimeRiskConflict("attempt event has no retained original consumption")
            preparation = preparations[event.attempt_id]
            if event.attempt_id not in attempts:
                if event.state is not SubmissionAttemptState.PENDING or not (
                    preparation.prepared_at
                    <= source.checked_at
                    < preparation.original_admission.expires_at
                ):
                    raise DailyRuntimeRiskConflict(
                        "new attempt must consume an unexpired original admission pending"
                    )
                hold = preparation.original_hold.commitment
                if (
                    known_bindings.get(hold.commitment_id) != preparation.original_hold
                    or any(item.order_id == hold.order_id for item in source.state.broker_events)
                    or any(item.order_id == hold.order_id for item in source.state.cancel_requests)
                ):
                    raise DailyRuntimeRiskConflict(
                        "pending consumption no longer has its original unsent hold"
                    )
                attempts[event.attempt_id] = reduce_daily_attempt(preparation, (event,))
            else:
                if event.sequence != len(attempts[event.attempt_id].events) + 1:
                    raise DailyRuntimeRiskConflict(
                        "event cannot be republished under a different parent command"
                    )
                attempts[event.attempt_id] = advance_daily_attempt(
                    attempts[event.attempt_id], event
                ).attempt
        dispatches = tuple(
            item.event.dispatch.record for item in envelopes if item.event.dispatch is not None
        )
        abandoned = tuple(item.event for item in envelopes if item.event.unsent_proof is not None)
        state = source.state
        if dispatches:
            if len(dispatches) != len(envelopes):
                raise DailyRuntimeRiskConflict(
                    "first-send activation requires its complete isolated batch"
                )
            if any(
                item.activation.heads != source.heads or item.activation.fence != source.fence
                for item in dispatches
            ):
                raise DailyRuntimeRiskConflict(
                    "first-send activation differs from actual source heads/fence"
                )
            prepared = prepare_daily_runtime_activation(
                state=source.state,
                context=source.context,
                execution_policy=source.execution_policy,
                attempts=tuple(current_attempts[item.event.attempt_id] for item in envelopes),
                dispatches=dispatches,
                accounting=self.accounting,
            )
            if prepared.command != source.accounting_command:
                raise DailyRuntimeRiskConflict("retained first-send accounting command differs")
            state = prepared.transition.state
        elif abandoned:
            if len(envelopes) != 1 or source.accounting_command is None:
                raise DailyRuntimeRiskConflict(
                    "unsent release requires one exact canonical command"
                )
            event = abandoned[0]
            proof = event.unsent_proof
            assert proof is not None
            prefix = current_attempts[event.attempt_id]
            hold = prefix.preparation.original_hold.commitment
            payload = ReleaseRuntimeUnsent(
                account_id=source.account_id,
                commitment_id=hold.commitment_id,
                expected_commitment_sha256=hold.semantic_sha256,
                source_state_sha256=source.state.semantic_sha256,
                attempt_history_sha256=prefix.semantic_sha256,
                locked_unsent_proof_sha256=proof.semantic_sha256,
                proof_at=proof.checked_at,
                reason=proof.reason,
                owner_command_sha256=None
                if proof.owner_command is None
                else proof.owner_command.semantic_sha256_ref,
            )
            if (
                source.accounting_command.payload != payload
                or proof.heads != source.heads
                or proof.fence != source.fence
                or proof.checked_at != source.checked_at
            ):
                raise DailyRuntimeRiskConflict("unsent release proof/accounting source differs")
            transition = self.accounting.advance(
                state=source.state,
                command=source.accounting_command,
                context=source.context,
                policy=source.execution_policy,
            )
            if (
                transition.disposition != "applied"
                or transition.reasons
                or transition.due_events
                or transition.journal_entries
            ):
                raise DailyRuntimeRiskConflict(
                    "canonical unsent release was not applied without broker effects"
                )
            state = transition.state
        elif source.accounting_command is not None:
            raise DailyRuntimeRiskConflict(
                "observed attempt outcome alone cannot manufacture financial effects"
            )
        replacements = dict(known_bindings)
        if len(state.commitments) != len(source.state.commitments):
            raise DailyRuntimeRiskConflict("attempt transition cannot add or erase hold identities")
        for item in state.commitments:
            original = known_bindings.get(item.commitment_id)
            if original is None:
                raise DailyRuntimeRiskConflict("attempt accounting introduced an unbound hold")
            replacements[item.commitment_id] = replace(original, commitment=item)
        return attempts, replacements, state

    def _resolve_attempt_history(
        self,
        raw: DailyRuntimeRawSnapshot,
        records: tuple[_AdmissionRecord, ...],
        rows: Mapping[str, tuple[Mapping[str, Any], ...]],
        original_holds: list[Mapping[str, Any]],
        original_heads: list[Mapping[str, Any]],
        *,
        resolved: ResolvedDailyRuntimeSnapshot | None = None,
    ) -> tuple[
        tuple[CanonicalDailyAttempt, ...],
        tuple[DailyAttemptEnvelope, ...],
        ResolvedRuntimeAttemptSources | None,
        list[Mapping[str, Any]],
        list[Mapping[str, Any]],
        tuple[DailyObservedHoldGroup, ...],
        ResolvedRuntimeObservedHoldSources | None,
    ]:
        if resolved is None:
            sources = self._resolved_attempt_sources(raw, records)
            observed_sources = self._resolved_observed_sources(raw)
        else:
            self.require_resolved_snapshot(resolved)
            if resolved.raw is not raw or resolved.admissions is not records:
                raise DailyRuntimeRiskConflict("original resolved source prefix differs")
            sources, observed_sources = resolved.attempt_sources, resolved.observed_sources
        observed = tuple(
            self._decode(row, DailyObservedHoldGroup) for row in rows[observed_hold_groups.name]
        )
        for row, retained_group in zip(rows[observed_hold_groups.name], observed, strict=True):
            if dict(row) != dict(self._observed_write(retained_group).values):
                raise DailyRuntimeRiskConflict("observed group index/content differs")
        observed_by_sequence = {group.coordinator_sequence: group for group in observed}
        if len(observed_by_sequence) != len(observed) or (observed and observed_sources is None):
            raise DailyRuntimeRiskConflict("complete observed group source history is missing")
        preparations: dict[str, DailyAttemptPreparation] = {}
        consumption_rows: dict[str, Mapping[str, Any]] = {}
        for row in rows[consumptions.name]:
            preparation = self._decode(row, DailyAttemptPreparation)
            expected = self._consumption_write(preparation, records)
            if dict(row) != dict(expected.values) or preparation.attempt_id in preparations:
                raise DailyRuntimeRiskConflict("original attempt consumption inventory differs")
            preparations[preparation.attempt_id] = preparation
            consumption_rows[preparation.attempt_id] = row
        envelopes = tuple(
            self._decode(row, DailyAttemptEnvelope) for row in rows[attempt_events.name]
        )
        for row, envelope in zip(rows[attempt_events.name], envelopes, strict=True):
            consumption = consumption_rows.get(envelope.event.attempt_id)
            if consumption is None or dict(self._event_write(envelope, consumption).values) != dict(
                row
            ):
                raise DailyRuntimeRiskConflict("indexed event/consumption/source metadata differs")
        if bool(preparations) != bool(envelopes) or (envelopes and sources is None):
            raise DailyRuntimeRiskConflict(
                "attempt history or authenticated source closure is missing"
            )
        groups: dict[int, list[DailyAttemptEnvelope]] = {}
        for envelope in envelopes:
            groups.setdefault(envelope.coordinator_sequence, []).append(envelope)
        if set(groups) & set(observed_by_sequence):
            raise DailyRuntimeRiskConflict(
                "attempt and observed groups reuse an account parent sequence"
            )
        by_source = (
            {}
            if sources is None
            else {source.semantic_sha256: source for source in sources.sources}
        )
        attempts: dict[str, CanonicalDailyAttempt] = {}
        bindings = {
            row["hold_id"]: self._decode(row, RuntimeCommitmentBinding) for row in original_holds
        }
        heads = {row["hold_id"]: row for row in original_heads}
        originals = {row["hold_id"]: row for row in original_holds}
        later = []
        ordered: list[DailyAttemptEnvelope] = []
        commands = set()
        watermark = 0
        observed_inputs = (
            {}
            if observed_sources is None
            else {item.source.semantic_sha256: item for item in observed_sources.inputs}
        )
        for sequence in sorted(set(groups) | set(observed_by_sequence)):
            if sequence in groups:
                group = tuple(sorted(groups[sequence], key=lambda item: item.event.attempt_id))
                source = by_source.get(group[0].source_ref.semantic_sha256)
                if (
                    source is None
                    or source.coordinator_command_id in commands
                    or source.heads.effect_watermark != watermark
                ):
                    raise DailyRuntimeRiskConflict("attempt account group/source sequence differs")
                commands.add(source.coordinator_command_id)
                attempts, updated, _ = self._apply_attempt_group(
                    envelopes=group,
                    source=source,
                    preparations=preparations,
                    current_attempts=attempts,
                    known_bindings=bindings,
                )
                ordered.extend(group)
            else:
                observed_group = observed_by_sequence[sequence]
                inputs = observed_inputs.get(observed_group.source_ref.semantic_sha256)
                if (
                    inputs is None
                    or inputs.source.coordinator_command_id in commands
                    or inputs.source.heads.effect_watermark != watermark
                    or inputs.source.heads.attempt_sha256
                    != daily_attempt_inventory_sha256(tuple(attempts.values()))
                ):
                    raise DailyRuntimeRiskConflict(
                        "observed group original attempt/effect head differs"
                    )
                result, updated = self._apply_observed_source(
                    inputs, observed_group.source_ref, bindings
                )
                if result.group != observed_group:
                    raise DailyRuntimeRiskConflict(
                        "observed group differs from complete canonical hold delta"
                    )
                commands.add(inputs.source.coordinator_command_id)
            for hold_id, binding in updated.items():
                if binding == bindings[hold_id]:
                    continue
                row = self._later_hold_values(originals[hold_id], heads[hold_id], binding)
                later.append(row)
                heads[hold_id] = MappingProxyType(
                    dict(
                        account_id=raw.account_id,
                        hold_id=hold_id,
                        revision=row["revision"],
                        semantic_sha256=binding.semantic_sha256,
                    )
                )
            bindings = updated
            watermark = sequence
        if set(attempts) != set(preparations) or sorted(
            rows[attempt_heads.name], key=lambda row: row["attempt_id"]
        ) != [self._attempt_head(attempts[key]) for key in sorted(attempts)]:
            raise DailyRuntimeRiskConflict(
                "complete attempt history and current head inventory differ"
            )
        return (
            tuple(attempts[key] for key in sorted(attempts)),
            tuple(ordered),
            sources,
            later,
            list(heads.values()),
            tuple(observed_by_sequence[key] for key in sorted(observed_by_sequence)),
            observed_sources,
        )

    def _later_hold_values(
        self,
        original: Mapping[str, Any],
        head: Mapping[str, Any],
        binding: RuntimeCommitmentBinding,
    ) -> Mapping[str, Any]:
        return MappingProxyType(
            dict(
                hold_id=original["hold_id"],
                revision=head["revision"] + 1,
                account_id=original["account_id"],
                admission_id=original["admission_id"],
                intent_id=original["intent_id"],
                execution_session=original["execution_session"],
                previous_sha256=head["semantic_sha256"],
                **self._encode(binding),
            )
        )

    def _resolved(self, snapshot: ResolvedDailyRuntimeSnapshot) -> None:
        self._require_owned(snapshot)
        self._require_owned(snapshot.raw)
        if (
            type(snapshot) is not ResolvedDailyRuntimeSnapshot
            or snapshot.seal is not self._seal
            or snapshot.raw.seal is not self._seal
        ):
            raise DailyRuntimeRiskConflict("resolved snapshot belongs to another store")

    def prepare_attempt_mutation(
        self,
        snapshot: ResolvedDailyRuntimeSnapshot,
        *,
        dispatch_journal: SqlDurableJournal | None = None,
        dispatch_appends: tuple[PreparedJournalAppend, ...] = (),
    ) -> PreparedDailyAttemptMutation:
        """Prepare exact indexed lifecycle and canonical holds; no SQL or delivery authority."""
        self._resolved(snapshot)
        raw, envelopes = snapshot.raw, snapshot.raw.requested_envelopes
        if not envelopes or snapshot.attempt_sources is None:
            raise DailyRuntimeRiskConflict(
                "attempt preparation requires its captured source command"
            )
        command_id, sequence = (
            envelopes[0].coordinator_command_id,
            envelopes[0].coordinator_sequence,
        )
        sources = [
            source
            for source in snapshot.attempt_sources.sources
            if source.semantic_sha256 == envelopes[0].source_ref.semantic_sha256
        ]
        if len(sources) != 1:
            raise DailyRuntimeRiskConflict("attempt source command is missing")
        source = sources[0]
        previous_group = tuple(
            item for item in snapshot.attempt_envelopes if item.coordinator_command_id == command_id
        )
        ordered = tuple(sorted(envelopes, key=lambda item: item.event.attempt_id))
        if previous_group and previous_group != ordered:
            raise DailyRuntimeRiskConflict("immutable attempt command retry conflicts")
        rows = {table.table: _typed_rows(table) for table in raw.tables}
        preparations = {attempt.attempt_id: attempt.preparation for attempt in snapshot.attempts}
        writes: list[_Write] = []
        for preparation in raw.requested_preparations:
            original = preparations.get(preparation.attempt_id)
            if original is not None and original != preparation:
                raise DailyRuntimeRiskConflict(
                    "attempt ID already consumes a different original admission"
                )
            if original is None:
                write = self._consumption_write(preparation, snapshot.admissions)
                writes.append(write)
                preparations[preparation.attempt_id] = preparation
        requested_ids = {item.event.attempt_id for item in envelopes}
        if any(item.attempt_id not in requested_ids for item in raw.requested_preparations):
            raise DailyRuntimeRiskConflict(
                "unrelated preparation cannot be consumed by an event group"
            )
        if previous_group:
            if writes or dispatch_appends or dispatch_journal is not None:
                raise DailyRuntimeRiskConflict(
                    "exact retry cannot create consumption or dispatch work"
                )
            prior_ids = {
                item.event.semantic_sha256
                for item in snapshot.attempt_envelopes
                if item.coordinator_sequence < sequence
            }
            attempts = {
                item.attempt_id: reduce_daily_attempt(
                    item.preparation,
                    tuple(event for event in item.events if event.semantic_sha256 in prior_ids),
                )
                for item in snapshot.attempts
                if any(event.semantic_sha256 in prior_ids for event in item.events)
            }
            bindings = {
                binding.commitment.commitment_id: binding for binding in source.obligations.bindings
            }
            after, changed, state = self._apply_attempt_group(
                envelopes=ordered,
                source=source,
                preparations=preparations,
                current_attempts=attempts,
                known_bindings=bindings,
            )
            result = DailyAttemptMutationResult(
                command_id,
                sequence,
                tuple(after[key] for key in sorted(after)),
                self._inventory(changed),
                state,
            )
            return self._own(
                PreparedDailyAttemptMutation(snapshot, result, (), (), None, True, None, ())
            )
        if sequence <= daily_runtime_effect_watermark(
            attempt_envelopes=snapshot.attempt_envelopes, observed_groups=snapshot.observed_groups
        ) or any(item.coordinator_command_id == command_id for item in snapshot.observed_groups):
            raise DailyRuntimeRiskConflict(
                "new account event group is not after complete retained history"
            )
        if (source.fence.fence, source.fence.policy_sha256, source.fence.lease_sha256) != (
            raw.receipt.fence,
            raw.receipt.policy_sha256,
            raw.receipt.lease_sha256,
        ):
            raise DailyRuntimeRiskConflict("new attempt source uses a different actual lease/fence")
        if (
            source.obligations != snapshot.obligations
            or not source.checked_at <= raw.receipt.validated_at < source.valid_until
        ):
            raise DailyRuntimeRiskConflict(
                "new attempt source inventory or actual capture time differs"
            )
        self._heads(snapshot, source.heads)
        if source.heads.effect_watermark != daily_runtime_effect_watermark(
            attempt_envelopes=snapshot.attempt_envelopes, observed_groups=snapshot.observed_groups
        ):
            raise DailyRuntimeRiskConflict("new attempt source effect watermark differs")
        creates_or_sends = any(
            item.event.state in (SubmissionAttemptState.PENDING, SubmissionAttemptState.IN_FLIGHT)
            for item in envelopes
        )
        if creates_or_sends and (
            snapshot.assignment is None
            or not snapshot.assignment.enabled_for_new_exposure
            or snapshot.control is None
            or snapshot.control.effective_state is not OperationalControlState.RUNNING
        ):
            raise DailyRuntimeRiskConflict(
                "new attempt/first send requires the enabled current assignment and running control"
            )
        if creates_or_sends and any(
            preparations[item.event.attempt_id].original_admission.evidence.assignment
            != snapshot.assignment
            for item in envelopes
            if item.event.attempt_id in preparations
        ):
            raise DailyRuntimeRiskConflict(
                "old policy admission cannot be silently rearmed under a new assignment"
            )
        current = {attempt.attempt_id: attempt for attempt in snapshot.attempts}
        bindings = {
            binding.commitment.commitment_id: binding for binding in snapshot.obligations.bindings
        }
        after, changed, state = self._apply_attempt_group(
            envelopes=ordered,
            source=source,
            preparations=preparations,
            current_attempts=current,
            known_bindings=bindings,
        )
        deadline = min(source.valid_until, raw.receipt.valid_until)
        consumption_rows = {row["attempt_id"]: row for row in rows[consumptions]}
        consumption_rows.update({write.values["attempt_id"]: write.values for write in writes})
        for envelope in ordered:
            event = envelope.event
            if event.state is SubmissionAttemptState.PENDING:
                deadline = min(
                    deadline, preparations[event.attempt_id].original_admission.expires_at
                )
            if event.dispatch is not None:
                deadline = min(deadline, event.dispatch.record.activation.expires_at)
            writes.append(self._event_write(envelope, consumption_rows[event.attempt_id]))
        if raw.receipt.validated_at >= deadline:
            raise DailyRuntimeRiskConflict(
                "original attempt/activation evidence expired before capture"
            )
        updates = []
        old_attempt_heads = {row["attempt_id"]: row for row in rows[attempt_heads]}
        for attempt_id in sorted(requested_ids):
            updates.append(
                _HeadUpdate(
                    attempt_heads,
                    old_attempt_heads.get(attempt_id),
                    self._attempt_head(after[attempt_id]),
                )
            )
        old_heads = {row["hold_id"]: row for row in rows[hold_heads]}
        originals = {row["hold_id"]: row for row in rows[hold_events] if row["revision"] == 1}
        for hold_id, binding in changed.items():
            if binding == bindings[hold_id]:
                continue
            values = self._later_hold_values(originals[hold_id], old_heads[hold_id], binding)
            writes.append(_Write(hold_events, values))
            updates.append(
                _HeadUpdate(
                    hold_heads,
                    old_heads[hold_id],
                    MappingProxyType(
                        dict(
                            account_id=raw.account_id,
                            hold_id=hold_id,
                            revision=values["revision"],
                            semantic_sha256=binding.semantic_sha256,
                        )
                    ),
                )
            )
        appends = self._prepare_dispatch_appends(ordered, dispatch_journal, dispatch_appends)
        result = DailyAttemptMutationResult(
            command_id,
            sequence,
            tuple(after[key] for key in sorted(after)),
            self._inventory(changed),
            state,
        )
        return self._own(
            PreparedDailyAttemptMutation(
                snapshot,
                result,
                tuple(writes),
                tuple(updates),
                deadline,
                False,
                dispatch_journal,
                appends,
            )
        )

    def _prepare_dispatch_appends(
        self,
        envelopes: tuple[DailyAttemptEnvelope, ...],
        journal: SqlDurableJournal | None,
        appends: tuple[PreparedJournalAppend, ...],
    ) -> tuple[PreparedJournalAppend, ...]:
        claims = tuple(item.event.dispatch for item in envelopes if item.event.dispatch is not None)
        if type(appends) is not tuple or any(
            type(item) is not PreparedJournalAppend for item in appends
        ):
            raise DailyRuntimeRiskConflict(
                "dispatch batch requires exact immutable prepared append records"
            )
        if not claims:
            if appends or journal is not None:
                raise DailyRuntimeRiskConflict("non-send lifecycle cannot append dispatch records")
            return ()
        if type(journal) is not SqlDurableJournal or len(appends) != len(claims):
            raise DailyRuntimeRiskConflict(
                "first send requires every separate prepared dispatch append"
            )
        by_command = {item.request.command_id: item for item in appends}
        if len(by_command) != len(appends):
            raise DailyRuntimeRiskConflict("dispatch appends duplicate a command")
        result = []
        for claim in claims:
            assert claim is not None
            append = by_command.get(claim.record.command_id)
            if append is None:
                raise DailyRuntimeRiskConflict("dispatch claim has no exact prepared append")
            expected = journal.prepare_append(append.key, append.request)
            request = claim.record.preparation.request
            scope = content_digest(
                (
                    "daily-dispatch-scope/1",
                    request.source_account_id,
                    request.source_account_binding_sha256,
                    request.venue_account_id,
                    request.venue_model,
                )
            )
            if (
                expected.receipt != claim.receipt
                or len(expected.entries) != 1
                or expected.entries[0].record.payload != self.codec.encode_record(claim.record)
                or expected.entries[0].record.record_id != claim.record.record_id
                or (
                    append.key.namespace,
                    append.key.account_scope,
                    append.key.source_provider,
                    append.key.source_environment,
                    append.key.source_scope_sha256,
                )
                != (
                    "coordinator",
                    request.source_account_id,
                    "daily-dispatch/1",
                    "synthetic",
                    scope,
                )
            ):
                raise DailyRuntimeRiskConflict("dispatch journal key/record/receipt scope differs")
            result.append(expected)
        result.sort(key=lambda item: item.receipt.previous_head.sequence)
        if any(
            left.receipt.committed_head != right.request.expected_head
            for left, right in pairwise(result)
        ):
            raise DailyRuntimeRiskConflict(
                "dispatch append batch is not one contiguous scoped stream"
            )
        return tuple(result)

    def commit_attempt_prepared_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedDailyAttemptMutation,
        *,
        fence: AccountFence,
    ) -> DailyAttemptMutationResult:
        """Atomically publish data under the caller transaction; returns no delivery token."""
        self._connection(connection)
        if type(prepared) is not PreparedDailyAttemptMutation:
            raise DailyRuntimeRiskConflict("exact store-produced lifecycle preparation required")
        self._require_attempt(prepared)
        with connection.begin_nested():
            receipt = self._recheck(connection, prepared.snapshot, fence)
            if prepared.valid_until is not None and receipt.validated_at >= prepared.valid_until:
                raise DailyRuntimeRiskConflict("attempt evidence expired before commit")
            if prepared.journal is not None:
                for append in prepared.dispatch_appends:
                    prepared.journal.append_in_transaction(connection, append)
            for write in prepared.writes:
                connection.execute(sa.insert(write.table).values(**write.values))
            for update in prepared.head_updates:
                if update.previous is None:
                    connection.execute(sa.insert(update.table).values(**update.values))
                else:
                    selected = next(iter(update.table.primary_key.columns))
                    value = connection.execute(
                        sa.update(update.table)
                        .where(
                            *(
                                update.table.c[name] == value
                                for name, value in update.previous.items()
                            )
                        )
                        .values(**update.values)
                        .returning(selected)
                    ).scalar_one_or_none()
                    if value != update.values[selected.name]:
                        raise DailyRuntimeRiskConflict(
                            "attempt/hold current head compare-and-swap failed"
                        )
            receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
            if prepared.valid_until is not None and receipt.validated_at >= prepared.valid_until:
                raise DailyRuntimeRiskConflict("attempt evidence expired before commit")
            return prepared.result

    def recheck_attempt_publication_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedDailyAttemptMutation,
        *,
        fence: AccountFence,
        prepared_account: object,
        account_receipt: object,
    ) -> DailyAttemptMutationResult:
        """Read back complete B and dispatch writes under the original C transaction."""
        self._connection(connection)
        self._require_attempt(prepared)
        raw = prepared.snapshot.raw
        if fence != raw.receipt.fence:
            raise DailyRuntimeRiskConflict("attempt publication fence differs")
        lock_account_capacity_serialization(connection, raw.account_id)
        self._no_legacy(connection, raw.account_id)
        self._recheck_publication_rows(connection, raw, prepared.writes, prepared.head_updates)
        if prepared.journal is not None:
            for index, append in enumerate(prepared.dispatch_appends):
                prepared.journal.recheck_prepared_append_in_transaction(
                    connection,
                    append,
                    require_current_head=index == len(prepared.dispatch_appends) - 1,
                )
        sources = prepared.snapshot.attempt_sources
        if sources is None:
            raise DailyRuntimeRiskConflict("attempt publication source is missing")
        for captured in sources.snapshot.tables:
            _recheck_table(connection, captured, exact_inventory=False)
        recheck = getattr(
            self._attempt_reader(), "recheck_attempt_sources_after_publication_in_transaction", None
        )
        if not callable(recheck):
            raise DailyRuntimeRiskConflict("attempt publication source pair reader is missing")
        recheck(
            connection, sources, prepared_account=prepared_account, account_receipt=account_receipt
        )
        receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        if prepared.valid_until is not None and receipt.validated_at >= prepared.valid_until:
            raise DailyRuntimeRiskConflict("attempt publication deadline expired")
        return prepared.result

    def recheck_completed_attempt_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedDailyAttemptMutation,
        *,
        fence: AccountFence,
        committed_sources: ResolvedCommittedContinuousRuntimeAttemptSources,
    ) -> DailyAttemptMutationResult:
        """Read back original completed B/dispatch/source rows; grants no delivery.

        Outside SQL the caller must require both the original B preparation and
        A's separately issued committed-source view. No pending C proof can enter
        this path, and historical restoration cannot recreate either ownership.
        """
        from packages.persistence.continuous_runtime_attempt_sources import (
            ResolvedCommittedContinuousRuntimeAttemptSources,
        )

        self._connection(connection)
        self._require_attempt(prepared)
        raw = prepared.snapshot.raw
        if (
            type(committed_sources) is not ResolvedCommittedContinuousRuntimeAttemptSources
            or committed_sources.original is not prepared.snapshot.attempt_sources
            or prepared.retry
            or fence != raw.receipt.fence
        ):
            raise DailyRuntimeRiskConflict(
                "completed attempt requires its original source and fence"
            )
        recheck = getattr(
            self._attempt_reader(), "recheck_committed_attempt_sources_in_transaction", None
        )
        if not callable(recheck):
            raise DailyRuntimeRiskConflict("completed attempt exact source reader is missing")
        lock_account_capacity_serialization(connection, raw.account_id)
        self._no_legacy(connection, raw.account_id)
        receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        if prepared.valid_until is not None and receipt.validated_at >= prepared.valid_until:
            raise DailyRuntimeRiskConflict("completed attempt deadline expired")
        # This actual A owner verifies its original view before its metadata is
        # used as the one allowed C append in the captured source footprint.
        recheck(connection, committed_sources)
        current = committed_sources.publication.snapshot.current
        previous = committed_sources.publication.snapshot.previous
        if (
            current.scope.account_id != raw.account_id
            or current.row["command_id"] != prepared.result.coordinator_command_id
            or current.row["sequence"] != prepared.result.coordinator_sequence
        ):
            raise DailyRuntimeRiskConflict("completed attempt original C publication differs")
        self._recheck_publication_rows(connection, raw, prepared.writes, prepared.head_updates)
        if prepared.journal is not None:
            for index, append in enumerate(prepared.dispatch_appends):
                prepared.journal.recheck_prepared_append_in_transaction(
                    connection,
                    append,
                    require_current_head=index == len(prepared.dispatch_appends) - 1,
                )
        captured_sources = (
            *raw.producer.tables,
            *(() if raw.attempt_sources is None else raw.attempt_sources.tables),
            *(() if raw.observed_sources is None else raw.observed_sources.tables),
        )
        c_tables = tuple(
            item for item in captured_sources if item.table is continuous_account_commits
        )
        if len(c_tables) != 1:
            raise DailyRuntimeRiskConflict("completed attempt original C inventory required")
        (original_c,) = c_tables
        if (
            previous is None
            or original_c.account_id != raw.account_id
            or not original_c.rows
            or len(original_c.rows) + 1 > MAX_ROWS
            or max(original_c.rows, key=lambda row: row["sequence"]) != previous.row
            or current.row["sequence"] != previous.row["sequence"] + 1
            or current.row["previous_commit_sha256"] != previous.row["commit_sha256"]
            or any(row["command_id"] == current.row["command_id"] for row in original_c.rows)
        ):
            raise DailyRuntimeRiskConflict("completed attempt original C prefix differs")
        budget = self._continued_budget(raw)
        budget.charge(1, *self._row_sizes(continuous_account_commits, current.row))
        for write in prepared.writes:
            budget.charge(1, *self._row_sizes(write.table, write.values))
        for update in prepared.head_updates:
            before = (
                (0, 0)
                if update.previous is None
                else self._row_sizes(update.table, update.previous)
            )
            after = self._row_sizes(update.table, update.values)
            budget.charge(
                int(update.previous is None),
                *(max(0, new - old) for new, old in zip(after, before, strict=True)),
            )
        for captured in captured_sources:
            _recheck_table(
                connection,
                RuntimeTableSnapshot(
                    continuous_account_commits,
                    raw.account_id,
                    (*original_c.rows, current.row),
                )
                if captured is original_c
                else captured,
            )
        if raw.producer.tables:
            self.producers.recheck_in_transaction(connection, raw.producer)
        if raw.observed_sources is not None:
            observed = prepared.snapshot.observed_sources
            if observed is None or observed.snapshot is not raw.observed_sources:
                raise DailyRuntimeRiskConflict("completed attempt observed history is incomplete")
            self._observed_reader().recheck_observed_hold_sources_in_transaction(
                connection, observed
            )
        recheck(connection, committed_sources)
        receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        if receipt.validated_at < raw.receipt.validated_at:
            raise DailyRuntimeRiskConflict("completed attempt clock regressed")
        if prepared.valid_until is not None and receipt.validated_at >= prepared.valid_until:
            raise DailyRuntimeRiskConflict("completed attempt deadline expired")
        return prepared.result

    def inspect_attempt_group(
        self,
        snapshot: ResolvedDailyRuntimeSnapshot,
        *,
        envelopes: tuple[DailyAttemptEnvelope, ...],
    ) -> RetainedDailyAttemptGroup:
        """Derive an original effect from already authenticated complete B history."""
        self.require_resolved_snapshot(snapshot)
        if not envelopes or snapshot.attempt_sources is None:
            raise DailyRuntimeRiskConflict("retained attempt source group required")
        command_id = envelopes[0].coordinator_command_id
        sequence = envelopes[0].coordinator_sequence
        original = tuple(
            item for item in snapshot.attempt_envelopes if item.coordinator_command_id == command_id
        )
        if original != envelopes:
            raise DailyRuntimeRiskConflict("original complete retained attempt group differs")
        sources = snapshot.attempt_sources
        matches = tuple(
            item
            for item in sources.sources
            if item.semantic_sha256 == envelopes[0].source_ref.semantic_sha256
        )
        if len(matches) != 1:
            raise DailyRuntimeRiskConflict("original retained attempt source differs")
        source = matches[0]
        prior_attempts = daily_runtime_attempt_prefix(
            attempts=snapshot.attempts,
            attempt_envelopes=snapshot.attempt_envelopes,
            through_coordinator_sequence=sequence - 1,
        )
        attempts, bindings, state = self._apply_attempt_group(
            envelopes=envelopes,
            source=source,
            preparations={item.attempt_id: item.preparation for item in snapshot.attempts},
            current_attempts={item.attempt_id: item for item in prior_attempts},
            known_bindings={
                item.commitment.commitment_id: item for item in source.obligations.bindings
            },
        )
        result = DailyAttemptMutationResult(
            command_id,
            sequence,
            tuple(attempts[key] for key in sorted(attempts)),
            self._inventory(bindings),
            state,
        )
        if result.attempts != daily_runtime_attempt_prefix(
            attempts=snapshot.attempts,
            attempt_envelopes=snapshot.attempt_envelopes,
            through_coordinator_sequence=sequence,
        ):
            raise DailyRuntimeRiskConflict("original canonical attempt result differs")
        rows = {table.table: table.rows for table in snapshot.raw.tables}
        # Identical financial values may recur after later corrections. Original
        # revision authority comes from complete causal prefix replay, not from
        # selecting a unique value hash in the latest inventory.
        typed = {item.table.name: _typed_rows(item) for item in snapshot.raw.tables}
        prefix_attempts = result.attempts
        prefix_ids = {item.attempt_id for item in prefix_attempts}
        typed[attempt_events.name] = tuple(
            row for row in typed[attempt_events.name] if row["coordinator_sequence"] <= sequence
        )
        typed[consumptions.name] = tuple(
            row for row in typed[consumptions.name] if row["attempt_id"] in prefix_ids
        )
        typed[attempt_heads.name] = tuple(self._attempt_head(item) for item in prefix_attempts)
        typed[observed_hold_groups.name] = tuple(
            row
            for row in typed[observed_hold_groups.name]
            if row["coordinator_sequence"] <= sequence
        )
        original_writes = tuple(
            write for record in snapshot.admissions for write in self._hold_writes(record)
        )
        original_holds = [write.values for write in original_writes if write.table is hold_events]
        original_heads = [write.values for write in original_writes if write.table is hold_heads]
        prefix = self._resolve_attempt_history(
            snapshot.raw,
            snapshot.admissions,
            typed,
            original_holds,
            original_heads,
            resolved=snapshot,
        )
        available = {row["hold_id"]: row["revision"] for row in prefix[4]}
        hold_limits = {
            binding.commitment.commitment_id: available[binding.commitment.commitment_id]
            for binding in result.obligations.bindings
        }
        latest = {
            row["hold_id"]: row
            for row in (*original_holds, *prefix[3])
            if row["hold_id"] in hold_limits and row["revision"] == hold_limits[row["hold_id"]]
        }
        if any(
            latest[binding.commitment.commitment_id]["semantic_sha256"] != binding.semantic_sha256
            for binding in result.obligations.bindings
        ):
            raise DailyRuntimeRiskConflict("original canonical attempt hold revision differs")
        hold_ids = tuple(sorted(hold_limits))
        admission_ids = tuple(
            sorted(
                {
                    row["admission_id"]
                    for row in rows[hold_events]
                    if row["hold_id"] in hold_limits and row["revision"] == 1
                }
            )
        )
        original_admissions = tuple(
            row for row in rows[admissions] if row["admission_id"] in admission_ids
        )
        generation = max((row["assignment_generation"] for row in original_admissions), default=0)
        prefix_events = tuple(
            row for row in rows[attempt_events] if row["coordinator_sequence"] <= sequence
        )
        attempt_ids = tuple(sorted({row["attempt_id"] for row in prefix_events}))
        selected = []
        for table, selected_rows, predicates in (
            (
                assignments,
                tuple(row for row in rows[assignments] if row["generation"] <= generation),
                (assignments.c.generation <= generation,),
            ),
            (admissions, original_admissions, (admissions.c.admission_id.in_(admission_ids),)),
            (
                hold_events,
                tuple(
                    row
                    for row in rows[hold_events]
                    if row["hold_id"] in hold_limits
                    and row["revision"] <= hold_limits[row["hold_id"]]
                ),
                (
                    hold_events.c.hold_id.in_(hold_ids),
                    hold_events.c.revision
                    <= sa.case(hold_limits, value=hold_events.c.hold_id, else_=0),
                ),
            ),
            (
                outbound,
                tuple(row for row in rows[outbound] if row["admission_id"] in admission_ids),
                (outbound.c.admission_id.in_(admission_ids),),
            ),
            (
                consumptions,
                tuple(row for row in rows[consumptions] if row["attempt_id"] in attempt_ids),
                (consumptions.c.attempt_id.in_(attempt_ids),),
            ),
            (attempt_events, prefix_events, (attempt_events.c.coordinator_sequence <= sequence,)),
            (
                observed_hold_groups,
                tuple(
                    row
                    for row in rows[observed_hold_groups]
                    if row["coordinator_sequence"] <= sequence
                ),
                (observed_hold_groups.c.coordinator_sequence <= sequence,),
            ),
            (
                phase5_operational_control_transitions,
                tuple(
                    row
                    for row in rows[phase5_operational_control_transitions]
                    if row["sequence_number"] <= source.heads.control_revision
                ),
                (
                    phase5_operational_control_transitions.c.sequence_number
                    <= source.heads.control_revision,
                ),
            ),
        ):
            selected.append(
                _ObservedHistoricalRows(
                    RuntimeTableSnapshot(table, snapshot.raw.account_id, selected_rows), predicates
                )
            )
        return self._own(
            RetainedDailyAttemptGroup(result, source, envelopes, sources, tuple(selected))
        )

    def recheck_attempt_group_in_transaction(
        self, connection: Connection, view: RetainedDailyAttemptGroup
    ) -> None:
        self._connection(connection)
        self._require_attempt(view)
        self._recheck_selected_history(connection, view.selected)
        for captured in view.sources.snapshot.tables:
            _recheck_table(connection, captured, exact_inventory=False)
        self._attempt_reader().recheck_attempt_sources_in_transaction(connection, view.sources)

    def _heads(self, snapshot: ResolvedDailyRuntimeSnapshot, heads: ReconciliationHeads) -> None:
        if (heads.capacity_sha256, heads.control_revision, heads.lease_generation) != (
            snapshot.obligations.semantic_sha256,
            0 if snapshot.control is None else snapshot.control.sequence_number,
            snapshot.raw.receipt.fence.fencing_generation,
        ):
            raise DailyRuntimeRiskConflict("current capacity/control/lease heads differ")

    def prepare_observed_holds(
        self,
        snapshot: ResolvedDailyRuntimeSnapshot,
    ) -> PreparedDailyObservedHolds:
        """Bind actual canonical hold changes; received financial facts need no risk renewal."""
        self._resolved(snapshot)
        raw = snapshot.raw
        reference = raw.requested_observed_source
        if reference is None or snapshot.observed_sources is None or raw.requested_envelopes:
            raise DailyRuntimeRiskConflict(
                "observed preparation requires one captured financial source"
            )
        source_inputs = self._resolved_observed_sources(raw)
        assert source_inputs is not None
        selected = [
            item
            for item in source_inputs.inputs
            if item.source.semantic_sha256 == reference.semantic_sha256
        ]
        if len(selected) != 1:
            raise DailyRuntimeRiskConflict("observed preparation source identity differs")
        inputs = selected[0]
        source = inputs.source
        existing = [
            item
            for item in snapshot.observed_groups
            if item.coordinator_command_id == source.coordinator_command_id
        ]
        bindings = {item.commitment.commitment_id: item for item in snapshot.obligations.bindings}
        if existing:
            if len(existing) != 1 or existing[0].source_ref != reference:
                raise DailyRuntimeRiskConflict("immutable observed parent/source retry conflict")
            original = {
                item.commitment_id: replace(bindings[item.commitment_id], commitment=item)
                for item in inputs.previous.state.commitments
                if item.commitment_id in bindings
            }
            result, _ = self._apply_observed_source(inputs, reference, original)
            if result.group != existing[0]:
                raise DailyRuntimeRiskConflict("original observed group replay differs")
            return self._own(PreparedDailyObservedHolds(snapshot, result, (), (), None, True))
        watermark = daily_runtime_effect_watermark(
            attempt_envelopes=snapshot.attempt_envelopes, observed_groups=snapshot.observed_groups
        )
        if (
            source.coordinator_sequence <= watermark
            or any(
                item.coordinator_command_id == source.coordinator_command_id
                for item in snapshot.attempt_envelopes
            )
            or source.heads.effect_watermark != watermark
            or source.heads.attempt_sha256 != daily_attempt_inventory_sha256(snapshot.attempts)
            or set(bindings) != {item.commitment_id for item in inputs.previous.state.commitments}
        ):
            raise DailyRuntimeRiskConflict("observed source complete current history/head differs")
        self._heads(snapshot, source.heads)
        if (source.fence.fence, source.fence.policy_sha256, source.fence.lease_sha256) != (
            raw.receipt.fence,
            raw.receipt.policy_sha256,
            raw.receipt.lease_sha256,
        ):
            raise DailyRuntimeRiskConflict("observed source current actual fence differs")
        deadline = min(source.valid_until, raw.receipt.valid_until)
        if not source.checked_at <= raw.receipt.validated_at < deadline:
            raise DailyRuntimeRiskConflict("observed current fence window expired before capture")
        result, _ = self._apply_observed_source(inputs, reference, bindings)
        rows = {table.table: _typed_rows(table) for table in raw.tables}
        original_rows = {row["hold_id"]: row for row in rows[hold_events] if row["revision"] == 1}
        heads = {row["hold_id"]: row for row in rows[hold_heads]}
        writes = [] if result.group is None else [self._observed_write(result.group)]
        updates = []
        for binding in result.changed_bindings:
            identity = binding.commitment.commitment_id
            values = self._later_hold_values(original_rows[identity], heads[identity], binding)
            writes.append(_Write(hold_events, values))
            updates.append(
                _HeadUpdate(
                    hold_heads,
                    heads[identity],
                    MappingProxyType(
                        dict(
                            account_id=raw.account_id,
                            hold_id=identity,
                            revision=values["revision"],
                            semantic_sha256=binding.semantic_sha256,
                        )
                    ),
                )
            )
        return self._own(
            PreparedDailyObservedHolds(
                snapshot, result, tuple(writes), tuple(updates), deadline, False
            )
        )

    def commit_observed_holds_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedDailyObservedHolds,
        *,
        fence: AccountFence,
    ) -> DailyObservedHoldResult:
        self._connection(connection)
        self._require_prepared_observed_holds(prepared)
        with connection.begin_nested():
            receipt = self._recheck(connection, prepared.snapshot, fence)
            if prepared.valid_until is not None and receipt.validated_at >= prepared.valid_until:
                raise DailyRuntimeRiskConflict(
                    "observed current fence window expired before commit"
                )
            for write in prepared.writes:
                connection.execute(sa.insert(write.table).values(**write.values))
            for update in prepared.head_updates:
                assert update.previous is not None
                actual = connection.execute(
                    sa.update(update.table)
                    .where(
                        *(update.table.c[name] == value for name, value in update.previous.items())
                    )
                    .values(**update.values)
                    .returning(update.table.c.hold_id)
                ).scalar_one_or_none()
                if actual != update.values["hold_id"]:
                    raise DailyRuntimeRiskConflict(
                        "observed hold current head compare-and-swap failed"
                    )
            receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
            if prepared.valid_until is not None and receipt.validated_at >= prepared.valid_until:
                raise DailyRuntimeRiskConflict(
                    "observed current fence window expired before commit"
                )
            return prepared.result

    def _recheck_publication_rows(
        self,
        connection: Connection,
        raw: DailyRuntimeRawSnapshot,
        writes: tuple[_Write, ...],
        head_updates: tuple[_HeadUpdate, ...],
    ) -> None:
        """Check the complete captured B/control footprint plus exactly these writes."""
        for captured in raw.tables:
            table = captured.table
            original = list(captured.rows)
            new_rows = [write.values for write in writes if write.table is table]
            for update in head_updates:
                if update.table is table:
                    if update.previous is not None:
                        if update.previous not in original:
                            raise DailyRuntimeRiskConflict("publication original head differs")
                        original.remove(update.previous)
                    new_rows.append(update.values)
            bounded = (
                sa.select(*table.primary_key.columns)
                .where(table.c.account_id == raw.account_id)
                .limit(MAX_ROWS + 1)
                .subquery()
            )
            if connection.scalar(sa.select(sa.func.count()).select_from(bounded)) != len(
                original
            ) + len(new_rows):
                raise DailyRuntimeRiskConflict("publication row inventory differs")
            _recheck_table(
                connection,
                RuntimeTableSnapshot(table, raw.account_id, tuple(original)),
                exact_inventory=False,
            )
            chunk = max(1, min(32, 800 // len(table.c)))
            for offset in range(0, len(new_rows), chunk):
                selected = new_rows[offset : offset + chunk]
                predicates = [
                    sa.and_(
                        *(
                            sa.and_(
                                _expressions(column, connection)[0],
                                column.is_(None)
                                if row[column.name] is None
                                else column == row[column.name],
                            )
                            for column in table.c
                        )
                    )
                    for row in selected
                ]
                matching = connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(table)
                    .where(table.c.account_id == raw.account_id, sa.or_(*predicates))
                )
                if matching != len(selected):
                    raise DailyRuntimeRiskConflict("publication written row differs")

    def recheck_observed_publication_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedDailyObservedHolds,
        *,
        fence: AccountFence,
        prepared_account: object | None = None,
        account_receipt: object | None = None,
    ) -> DailyObservedHoldResult:
        """Authenticate exact B post-write footprint in the still-owned outer transaction."""
        self._connection(connection)
        self._require_prepared_observed_holds(prepared)
        self.require_resolved_snapshot(prepared.snapshot)
        if (prepared_account is None) != (account_receipt is None):
            raise DailyRuntimeRiskConflict("observed publication requires the exact account pair")
        raw = prepared.snapshot.raw
        if fence != raw.receipt.fence:
            raise DailyRuntimeRiskConflict("observed publication fence differs")
        lock_account_capacity_serialization(connection, raw.account_id)
        self._no_legacy(connection, raw.account_id)
        self._recheck_publication_rows(connection, raw, prepared.writes, prepared.head_updates)
        if (
            prepared.snapshot.observed_sources is None
            or prepared.snapshot.observed_sources.snapshot is not raw.observed_sources
        ):
            raise DailyRuntimeRiskConflict("observed publication source is missing")
        for captured in prepared.snapshot.observed_sources.snapshot.tables:
            _recheck_table(connection, captured, exact_inventory=False)
        reader = self._observed_reader()
        if prepared_account is None:
            reader.recheck_observed_hold_sources_in_transaction(
                connection, prepared.snapshot.observed_sources
            )
        else:
            after_publication = getattr(
                reader, "recheck_observed_hold_sources_after_publication_in_transaction", None
            )
            if not callable(after_publication):
                raise DailyRuntimeRiskConflict("observed publication source pair reader is missing")
            after_publication(
                connection,
                prepared.snapshot.observed_sources,
                prepared_account=prepared_account,
                account_receipt=account_receipt,
            )
        if raw.attempt_sources is not None:
            attempts = prepared.snapshot.attempt_sources
            if attempts is None or attempts.snapshot is not raw.attempt_sources:
                raise DailyRuntimeRiskConflict("observed publication attempt source differs")
            for captured in raw.attempt_sources.tables:
                _recheck_table(connection, captured, exact_inventory=False)
            attempt_reader = self._attempt_reader()
            if prepared_account is None:
                attempt_reader.recheck_attempt_sources_in_transaction(connection, attempts)
            else:
                recheck_attempts = getattr(
                    attempt_reader,
                    "recheck_attempt_sources_after_publication_in_transaction",
                    None,
                )
                if not callable(recheck_attempts):
                    raise DailyRuntimeRiskConflict(
                        "observed publication original attempt reader is missing"
                    )
                recheck_attempts(
                    connection,
                    attempts,
                    prepared_account=prepared_account,
                    account_receipt=account_receipt,
                )
        elif prepared.snapshot.attempt_sources is not None:
            raise DailyRuntimeRiskConflict("observed publication unexpected attempt source")
        # Source readback must not conceal a later mutation of the exact B write set.
        self._recheck_publication_rows(connection, raw, prepared.writes, prepared.head_updates)
        receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        if prepared.valid_until is not None and receipt.validated_at >= prepared.valid_until:
            raise DailyRuntimeRiskConflict("observed publication deadline expired")
        return prepared.result

    def inspect_assignment_prefix(
        self,
        snapshot: ResolvedDailyRuntimeSnapshot,
        *,
        assignment_generation: int,
        through_coordinator_sequence: int,
        commitment_ids: tuple[str, ...],
    ) -> RetainedDailyAssignmentPrefix:
        """Inspect original B history after full replay; this does not authenticate C's cutoff."""
        self.require_resolved_snapshot(snapshot)
        if (
            type(assignment_generation) is not int
            or not 1 <= assignment_generation <= len(snapshot.assignment_rows)
            or type(through_coordinator_sequence) is not int
            or not 0 <= through_coordinator_sequence < 2**63
            or type(commitment_ids) is not tuple
            or any(type(item) is not str for item in commitment_ids)
            or commitment_ids != tuple(sorted(set(commitment_ids)))
            or len(commitment_ids) > MAX_ROWS
        ):
            raise DailyRuntimeRiskConflict("original assignment prefix selection differs")
        checked = snapshot
        rows = {item.table: item.rows for item in snapshot.raw.tables}
        typed = {item.table.name: _typed_rows(item) for item in snapshot.raw.tables}
        assignment_row = typed[assignments.name][assignment_generation - 1]
        command = self.codec.decode_record(
            assignment_row["command_payload"], RuntimeAssignmentCommand
        )
        recorded_at = assignment_row["recorded_at"]
        after = checked.assignment_rows[assignment_generation - 1]
        before = (
            None
            if assignment_generation == 1
            else checked.assignment_rows[assignment_generation - 2]
        )
        sequence = through_coordinator_sequence
        attempts = daily_runtime_attempt_prefix(
            attempts=checked.attempts,
            attempt_envelopes=checked.attempt_envelopes,
            through_coordinator_sequence=sequence,
        )
        attempt_ids = tuple(sorted(item.attempt_id for item in attempts))
        typed[attempt_events.name] = tuple(
            row for row in typed[attempt_events.name] if row["coordinator_sequence"] <= sequence
        )
        typed[consumptions.name] = tuple(
            row for row in typed[consumptions.name] if row["attempt_id"] in attempt_ids
        )
        typed[attempt_heads.name] = tuple(self._attempt_head(item) for item in attempts)
        typed[observed_hold_groups.name] = tuple(
            row
            for row in typed[observed_hold_groups.name]
            if row["coordinator_sequence"] <= sequence
        )
        original_writes = tuple(
            write for record in checked.admissions for write in self._hold_writes(record)
        )
        original_holds = [write.values for write in original_writes if write.table is hold_events]
        original_heads = [write.values for write in original_writes if write.table is hold_heads]
        prefix = self._resolve_attempt_history(
            snapshot.raw,
            checked.admissions,
            typed,
            original_holds,
            original_heads,
            resolved=checked,
        )
        available = {row["hold_id"]: row["revision"] for row in prefix[4]}
        if any(identifier not in available for identifier in commitment_ids):
            raise DailyRuntimeRiskConflict(
                "original C commitment is missing from retained B history"
            )
        limits = {identifier: available[identifier] for identifier in commitment_ids}
        latest = {
            row["hold_id"]: row
            for row in (*original_holds, *prefix[3])
            if row["hold_id"] in limits and row["revision"] == limits[row["hold_id"]]
        }
        bindings = tuple(
            self._decode(latest[identifier], RuntimeCommitmentBinding)
            for identifier in commitment_ids
        )
        obligations = RuntimeObligationInventory(
            bindings=bindings,
            legacy_universe_sha256=content_digest(()),
            daily_universe_sha256=content_digest(bindings),
        )
        original_admission_ids = tuple(
            sorted(
                {
                    row["admission_id"]
                    for row in rows[hold_events]
                    if row["hold_id"] in limits and row["revision"] == 1
                }
            )
        )
        control_revision = command.expected_heads.control_revision
        controls = _verified_history_from_rows(
            account_id=snapshot.raw.account_id,
            transition_rows=tuple(
                sorted(
                    typed[phase5_operational_control_transitions.name],
                    key=lambda row: cast(int, row["sequence_number"]),
                )
            ),
            completion_rows=_completion_rows_index(
                typed[phase5_operational_control_completions.name]
            ),
            head_row=next(iter(typed[phase5_operational_control_heads.name]), None),
        )
        if not 0 <= control_revision <= len(controls):
            raise DailyRuntimeRiskConflict("original assignment control revision is not retained")
        control = None if control_revision == 0 else controls[control_revision - 1].transition
        selected = []
        for table, selected_rows, predicates in (
            (
                assignments,
                tuple(
                    row for row in rows[assignments] if row["generation"] <= assignment_generation
                ),
                (assignments.c.generation <= assignment_generation,),
            ),
            (
                admissions,
                tuple(
                    row for row in rows[admissions] if row["admission_id"] in original_admission_ids
                ),
                (admissions.c.admission_id.in_(original_admission_ids),),
            ),
            (
                hold_events,
                tuple(
                    row
                    for row in rows[hold_events]
                    if row["hold_id"] in limits and row["revision"] <= limits[row["hold_id"]]
                ),
                (
                    hold_events.c.hold_id.in_(commitment_ids),
                    hold_events.c.revision <= sa.case(limits, value=hold_events.c.hold_id, else_=0)
                    if limits
                    else sa.false(),
                ),
            ),
            (
                outbound,
                tuple(
                    row for row in rows[outbound] if row["admission_id"] in original_admission_ids
                ),
                (outbound.c.admission_id.in_(original_admission_ids),),
            ),
            (
                consumptions,
                tuple(row for row in rows[consumptions] if row["attempt_id"] in attempt_ids),
                (consumptions.c.attempt_id.in_(attempt_ids),),
            ),
            (
                attempt_events,
                tuple(
                    row for row in rows[attempt_events] if row["coordinator_sequence"] <= sequence
                ),
                (attempt_events.c.coordinator_sequence <= sequence,),
            ),
            (
                observed_hold_groups,
                tuple(
                    row
                    for row in rows[observed_hold_groups]
                    if row["coordinator_sequence"] <= sequence
                ),
                (observed_hold_groups.c.coordinator_sequence <= sequence,),
            ),
            (
                phase5_operational_control_transitions,
                tuple(
                    row
                    for row in rows[phase5_operational_control_transitions]
                    if row["sequence_number"] <= control_revision
                ),
                (phase5_operational_control_transitions.c.sequence_number <= control_revision,),
            ),
            (
                phase5_operational_control_completions,
                tuple(
                    row
                    for row in rows[phase5_operational_control_completions]
                    if row["head_sequence_number"] <= control_revision
                    and as_aware_utc(row["observed_at"]) <= recorded_at
                ),
                (
                    phase5_operational_control_completions.c.head_sequence_number
                    <= control_revision,
                    phase5_operational_control_completions.c.observed_at <= recorded_at,
                ),
            ),
        ):
            selected.append(
                _ObservedHistoricalRows(
                    RuntimeTableSnapshot(table, snapshot.raw.account_id, selected_rows), predicates
                )
            )
        return self._own(
            RetainedDailyAssignmentPrefix(
                checked,
                before,
                after,
                command,
                recorded_at,
                sequence,
                commitment_ids,
                obligations,
                prefix[0],
                prefix[1],
                prefix[5],
                control,
                tuple(selected),
            )
        )

    def recheck_assignment_prefix_in_transaction(
        self, connection: Connection, view: RetainedDailyAssignmentPrefix
    ) -> None:
        """Authenticate immutable selected B/control rows, allowing later heads and history."""
        self._connection(connection)
        self._require_assignment_prefix(view)
        self._recheck_selected_history(connection, view.selected)
        snapshot = view.snapshot
        if snapshot.attempt_sources is not None:
            for captured in snapshot.attempt_sources.snapshot.tables:
                _recheck_table(connection, captured, exact_inventory=False)
            self._attempt_reader().recheck_attempt_sources_in_transaction(
                connection, snapshot.attempt_sources
            )
        if snapshot.observed_sources is not None:
            for captured in snapshot.observed_sources.snapshot.tables:
                _recheck_table(connection, captured, exact_inventory=False)
            self._observed_reader().recheck_observed_hold_sources_in_transaction(
                connection, snapshot.observed_sources
            )

    @staticmethod
    def _recheck_selected_history(
        connection: Connection, selected_rows: tuple[_ObservedHistoricalRows, ...]
    ) -> None:
        for selected in selected_rows:
            captured = selected.snapshot
            table = captured.table
            bounded = (
                sa.select(*table.primary_key.columns)
                .where(table.c.account_id == captured.account_id, *selected.predicates)
                .limit(MAX_ROWS + 1)
                .subquery()
            )
            if connection.scalar(sa.select(sa.func.count()).select_from(bounded)) != len(
                captured.rows
            ):
                raise DailyRuntimeRiskConflict("original selected row inventory changed")
            _recheck_table(connection, captured, exact_inventory=False)

    def inspect_observed_group(
        self,
        snapshot: ResolvedDailyRuntimeSnapshot,
        *,
        group: DailyObservedHoldGroup,
    ) -> RetainedDailyObservedHolds:
        """Reconstruct a retained original result without current heads or renewed time."""
        self._resolved(snapshot)
        # Full retained prefix authentication is detached and does not revalidate a fence.
        checked = self.resolve_snapshot(snapshot.raw)
        if type(group) is not DailyObservedHoldGroup or group not in checked.observed_groups:
            raise DailyRuntimeRiskConflict("original observed group is not retained")
        assert checked.observed_sources is not None
        inputs = next(
            item
            for item in checked.observed_sources.inputs
            if item.source.semantic_sha256 == group.source_ref.semantic_sha256
        )
        current = {item.commitment.commitment_id: item for item in checked.obligations.bindings}
        original = {
            item.commitment_id: replace(current[item.commitment_id], commitment=item)
            for item in inputs.previous.state.commitments
            if item.commitment_id in current
        }
        result, _ = self._apply_observed_source(inputs, group.source_ref, original)
        if result.group != group:
            raise DailyRuntimeRiskConflict("original observed inspection result differs")
        rows = {captured.table: captured.rows for captured in snapshot.raw.tables}
        sequence = group.coordinator_sequence
        attempt_prefix = daily_runtime_attempt_prefix(
            attempts=checked.attempts,
            attempt_envelopes=checked.attempt_envelopes,
            through_coordinator_sequence=sequence,
        )
        prefix_ids = {item.attempt_id for item in attempt_prefix}
        prefix_rows = {
            captured.table.name: _typed_rows(captured) for captured in snapshot.raw.tables
        }
        prefix_rows[attempt_events.name] = tuple(
            row
            for row in prefix_rows[attempt_events.name]
            if row["coordinator_sequence"] <= sequence
        )
        prefix_rows[consumptions.name] = tuple(
            row for row in prefix_rows[consumptions.name] if row["attempt_id"] in prefix_ids
        )
        prefix_rows[attempt_heads.name] = tuple(self._attempt_head(item) for item in attempt_prefix)
        prefix_rows[observed_hold_groups.name] = tuple(
            row
            for row in prefix_rows[observed_hold_groups.name]
            if row["coordinator_sequence"] <= sequence
        )
        original_writes = tuple(
            write for record in checked.admissions for write in self._hold_writes(record)
        )
        original_holds = [write.values for write in original_writes if write.table is hold_events]
        original_heads = [write.values for write in original_writes if write.table is hold_heads]
        prefix = self._resolve_attempt_history(
            snapshot.raw, checked.admissions, prefix_rows, original_holds, original_heads
        )
        hold_limits = {
            row["hold_id"]: row["revision"]
            for row in prefix[4]
            if row["hold_id"]
            in {binding.commitment.commitment_id for binding in result.after.bindings}
        }
        ids = tuple(sorted(hold_limits))
        admission_ids = tuple(
            sorted(
                {
                    row["admission_id"]
                    for row in rows[hold_events]
                    if row["hold_id"] in hold_limits and row["revision"] == 1
                }
            )
        )
        original_admissions = tuple(
            row for row in rows[admissions] if row["admission_id"] in admission_ids
        )
        generation = max((row["assignment_generation"] for row in original_admissions), default=0)
        sequence = group.coordinator_sequence
        original_events = tuple(
            row for row in rows[attempt_events] if row["coordinator_sequence"] <= sequence
        )
        attempt_ids = tuple(sorted({row["attempt_id"] for row in original_events}))
        selected = []
        for table, selected_rows, predicates in (
            (
                assignments,
                tuple(row for row in rows[assignments] if row["generation"] <= generation),
                (assignments.c.generation <= generation,),
            ),
            (admissions, original_admissions, (admissions.c.admission_id.in_(admission_ids),)),
            (
                hold_events,
                tuple(
                    row
                    for row in rows[hold_events]
                    if row["hold_id"] in hold_limits
                    and row["revision"] <= hold_limits[row["hold_id"]]
                ),
                (
                    hold_events.c.hold_id.in_(ids),
                    hold_events.c.revision
                    <= sa.case(hold_limits, value=hold_events.c.hold_id, else_=0),
                ),
            ),
            (
                outbound,
                tuple(row for row in rows[outbound] if row["admission_id"] in admission_ids),
                (outbound.c.admission_id.in_(admission_ids),),
            ),
            (
                consumptions,
                tuple(row for row in rows[consumptions] if row["attempt_id"] in attempt_ids),
                (consumptions.c.attempt_id.in_(attempt_ids),),
            ),
            (attempt_events, original_events, (attempt_events.c.coordinator_sequence <= sequence,)),
            (
                observed_hold_groups,
                tuple(
                    row
                    for row in rows[observed_hold_groups]
                    if row["coordinator_sequence"] <= sequence
                ),
                (observed_hold_groups.c.coordinator_sequence <= sequence,),
            ),
        ):
            selected.append(
                _ObservedHistoricalRows(
                    RuntimeTableSnapshot(table, snapshot.raw.account_id, selected_rows), predicates
                )
            )
        return self._own(
            RetainedDailyObservedHolds(result, inputs, checked.observed_sources, tuple(selected))
        )

    def recheck_observed_group_in_transaction(
        self,
        connection: Connection,
        view: RetainedDailyObservedHolds,
    ) -> None:
        """Check immutable original rows, allowing later valid heads and history."""
        self._connection(connection)
        self._require_observed_group_view(view)
        self._recheck_selected_history(connection, view.selected)
        for captured in view.sources.snapshot.tables:
            _recheck_table(connection, captured, exact_inventory=False)
        self._observed_reader().recheck_observed_hold_sources_in_transaction(
            connection, view.sources
        )

    def _encode(self, value: ContractRecord) -> dict[str, object]:
        payload = self.codec.encode_record(value)
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_BYTES:
            raise DailyRuntimeRiskConflict("daily record exceeds its byte bound")
        return dict(
            semantic_sha256=value.semantic_sha256,
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            payload=payload,
        )

    def _decode(self, row: Mapping[str, Any], cls: type[T]) -> T:
        payload = row["payload"]
        if (
            type(payload) is not bytes
            or not 0 < len(payload) <= MAX_BYTES
            or hashlib.sha256(payload).hexdigest() != row["payload_sha256"]
        ):
            raise DailyRuntimeRiskConflict("daily record byte identity differs")
        value = self.codec.decode_record(payload, cls)
        if (
            type(value) is not cls
            or self.codec.encode_record(value) != payload
            or value.semantic_sha256 != row["semantic_sha256"]
        ):
            raise DailyRuntimeRiskConflict("daily record canonical identity differs")
        return value

    def _admission_view(self, row: Mapping[str, Any]) -> RetainedDailyAdmission:
        record = self._decode(row, _AdmissionRecord)
        admission, resolved = record.admission, record.resolved
        assignment = admission.evidence.assignment
        identifier = content_digest(("daily-admission/1", assignment.account_id, record.command_id))
        if (
            tuple(
                row[name]
                for name in (
                    "admission_id",
                    "account_id",
                    "command_id",
                    "request_sha256",
                    "batch_sha256",
                    "assignment_generation",
                    "assignment_sha256",
                    "approved",
                )
            )
            != (
                identifier,
                assignment.account_id,
                record.command_id,
                record.request_sha256,
                admission.decision.batch.semantic_sha256,
                assignment.generation,
                assignment.semantic_sha256,
                admission.decision.approved,
            )
            or resolved.inputs != admission.evidence.inputs
            or resolved.producer_map != admission.evidence.producer_map
            or resolved.snapshot.semantic_sha256 != admission.evidence.snapshot_sha256
            or resolved.state.account_id != assignment.account_id
            or resolved.context.point.knowledge_at != resolved.snapshot.point.knowledge_at
            or resolved.snapshot.point.knowledge_at != admission.evidence.produced_at
        ):
            raise DailyRuntimeRiskConflict("retained admission source/metadata differs")
        decision = evaluate_daily_risk(
            assignment.policy,
            resolved.snapshot,
            admission.decision.batch,
            admission.evidence,
            admission.evidence.produced_at,
        )
        if decision != admission.decision:
            raise DailyRuntimeRiskConflict("retained admission risk replay differs")
        expected = (
            self._prepare(resolved, decision.batch, decision, assignment.policy)
            if decision.approved
            else ()
        )
        if expected != record.prepared_commitments:
            raise DailyRuntimeRiskConflict("retained admission canonical install differs")
        return self._own(
            RetainedDailyAdmission(
                record.command_id,
                record.request_sha256,
                record.semantic_sha256,
                row["payload"],
                row["payload_sha256"],
                admission,
                resolved,
                record.prepared_commitments,
                self._bindings(record),
            )
        )

    def inspect_prepared_admission(
        self, prepared: PreparedDailyAdmission
    ) -> RetainedDailyAdmission:
        """Inspect owned preparation outside SQL without changing its serialized producer."""
        self._require_owned(prepared)
        if type(prepared) is not PreparedDailyAdmission:
            raise DailyRuntimeRiskConflict("exact prepared admission required")
        self._resolved(prepared.snapshot)
        command_id = prepared.snapshot.raw.command_id
        candidates = (
            tuple(
                row
                for table in prepared.snapshot.raw.tables
                if table.table is admissions
                for row in _typed_rows(table)
                if row["command_id"] == command_id
            )
            if prepared.retry
            else tuple(w.values for w in prepared.writes if w.table is admissions)
        )
        if len(candidates) != 1:
            raise DailyRuntimeRiskConflict("prepared admission record inventory differs")
        view = self._admission_view(candidates[0])
        if view.command_id != command_id or view.admission != prepared.result:
            raise DailyRuntimeRiskConflict("prepared admission result differs from original record")
        return view

    def inspect_snapshot_admissions(
        self, snapshot: ResolvedDailyRuntimeSnapshot
    ) -> tuple[RetainedDailyAdmission, ...]:
        """Inspect original retained admissions from a fully resolved owned snapshot.

        Historical admission times and verdicts remain unchanged. This detached
        inspection creates no decision, reservation, command or send authority.
        """
        self.require_resolved_snapshot(snapshot)
        tables = [table for table in snapshot.raw.tables if table.table is admissions]
        if len(tables) != 1:
            raise DailyRuntimeRiskConflict("original admission table inventory differs")
        values = tuple(self._admission_view(row) for row in _typed_rows(tables[0]))
        expected = tuple(
            sorted((record.command_id, record.semantic_sha256) for record in snapshot.admissions)
        )
        if (
            len({value.command_id for value in values}) != len(values)
            or tuple(sorted((value.command_id, value.record_sha256) for value in values))
            != expected
        ):
            raise DailyRuntimeRiskConflict("original resolved admission inventory differs")
        self.require_resolved_snapshot(snapshot)
        return tuple(sorted(values, key=lambda value: value.command_id))

    def require_admission_view(self, view: RetainedDailyAdmission) -> None:
        self._require_owned(view)
        if type(view) is not RetainedDailyAdmission:
            raise DailyRuntimeRiskConflict("exact retained admission inspection required")

    def capture_historical_admission_in_transaction(
        self,
        connection: Connection,
        *,
        account_id: str,
        command_id: str,
        expected_record_sha256: str,
        budget: RuntimeReadBudget | None = None,
    ) -> HistoricalDailyAdmissionSnapshot:
        """Capture original immutable admission rows; no clock, fence creation or decoding."""
        self._connection(connection)
        require_identifier(account_id, "account")
        require_identifier(command_id, "command")
        require_digest(expected_record_sha256, "retained admission record")
        budget = RuntimeReadBudget() if budget is None else budget
        first = _capture_runtime_rows(
            connection,
            admissions,
            account_id=account_id,
            budget=budget,
            extra=(admissions.c.command_id == command_id,),
        )
        if len(first.rows) != 1:
            raise DailyRuntimeRiskConflict("historical admission is missing or duplicated")
        row = first.rows[0]
        if row["semantic_sha256"] != expected_record_sha256 or (
            type(row["assignment_generation"]) is not int
            or not 1 <= row["assignment_generation"] <= MAX_ROWS
        ):
            raise DailyRuntimeRiskConflict("historical admission identity/generation differs")
        tables = (
            first,
            _capture_runtime_rows(
                connection,
                assignments,
                account_id=account_id,
                budget=budget,
                extra=(assignments.c.generation <= row["assignment_generation"],),
            ),
            _capture_runtime_rows(
                connection,
                hold_events,
                account_id=account_id,
                budget=budget,
                extra=(
                    hold_events.c.admission_id == row["admission_id"],
                    hold_events.c.revision == 1,
                ),
            ),
            _capture_runtime_rows(
                connection,
                outbound,
                account_id=account_id,
                budget=budget,
                extra=(outbound.c.admission_id == row["admission_id"],),
            ),
        )
        return self._own(
            HistoricalDailyAdmissionSnapshot(
                account_id,
                command_id,
                expected_record_sha256,
                tables,
            )
        )

    def resolve_historical_admission(
        self,
        snapshot: HistoricalDailyAdmissionSnapshot,
    ) -> ResolvedHistoricalDailyAdmission:
        self._require_owned(snapshot)
        if type(snapshot) is not HistoricalDailyAdmissionSnapshot:
            raise DailyRuntimeRiskConflict("exact historical capture required")
        rows = {table.table: _typed_rows(table) for table in snapshot.tables}
        view = self._admission_view(rows[admissions][0])
        if (
            view.command_id != snapshot.command_id
            or view.record_sha256 != snapshot.expected_record_sha256
        ):
            raise DailyRuntimeRiskConflict("historical inspection scope differs")
        assignment = view.admission.evidence.assignment
        previous = None
        for generation, row in enumerate(rows[assignments], 1):
            value = self._decode(row, RuntimeRiskAssignment)
            command = self.codec.decode_record(row["command_payload"], RuntimeAssignmentCommand)
            if (
                (value.account_id, value.generation, value.previous_assignment_sha256)
                != (snapshot.account_id, generation, previous)
                or (row["account_id"], row["generation"], row["previous_sha256"])
                != (snapshot.account_id, generation, previous)
                or value.account_binding_sha256 != assignment.account_binding_sha256
                or (generation == 1 and value.enabled_for_new_exposure)
                or self.codec.encode_record(command) != row["command_payload"]
                or (
                    command.command_id,
                    command.semantic_sha256,
                    command.account_id,
                    command.before_assignment_sha256,
                    command.after_assignment_sha256,
                )
                != (
                    row["command_id"],
                    row["command_sha256"],
                    snapshot.account_id,
                    previous,
                    value.semantic_sha256,
                )
                or not command.requested_at <= row["recorded_at"] < command.expires_at
            ):
                raise DailyRuntimeRiskConflict("historical assignment prefix differs")
            previous = value.semantic_sha256
        if (
            len(rows[assignments]) != assignment.generation
            or previous != assignment.semantic_sha256
        ):
            raise DailyRuntimeRiskConflict("historical admission assignment is missing")
        record = self._decode(rows[admissions][0], _AdmissionRecord)
        writes = self._hold_writes(record)
        for table in (hold_events, outbound):
            expected = sorted(
                (dict(w.values) for w in writes if w.table is table), key=lambda r: r["hold_id"]
            )
            if sorted(rows[table], key=lambda r: r["hold_id"]) != expected:
                raise DailyRuntimeRiskConflict(
                    "historical original hold/outbound inventory differs"
                )
        return self._own(ResolvedHistoricalDailyAdmission(snapshot, view))

    def recheck_historical_admission_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedHistoricalDailyAdmission,
    ) -> None:
        """Recheck immutable original rows, permitting legitimate later history and heads."""
        self._connection(connection)
        self._require_owned(resolved)
        if type(resolved) is not ResolvedHistoricalDailyAdmission:
            raise DailyRuntimeRiskConflict("exact resolved historical admission required")
        snapshot = resolved.snapshot
        self._require_owned(snapshot)
        self.require_admission_view(resolved.admission)
        first = snapshot.tables[0].rows[0]
        for captured in snapshot.tables:
            table = captured.table
            predicates = [table.c.account_id == snapshot.account_id]
            if table is assignments:
                predicates.append(table.c.generation <= first["assignment_generation"])
            elif table is admissions:
                predicates.append(table.c.command_id == snapshot.command_id)
            else:
                predicates.append(table.c.admission_id == first["admission_id"])
                if table is hold_events:
                    predicates.append(table.c.revision == 1)
            bounded = (
                sa.select(*table.primary_key.columns)
                .where(*predicates)
                .limit(MAX_ROWS + 1)
                .subquery()
            )
            if connection.scalar(sa.select(sa.func.count()).select_from(bounded)) != len(
                captured.rows
            ):
                raise DailyRuntimeRiskConflict("historical selected row inventory changed")
            _recheck_table(connection, captured, exact_inventory=False)

    def recheck_snapshot_in_transaction(
        self,
        connection: Connection,
        snapshot: ResolvedDailyRuntimeSnapshot,
        *,
        fence: AccountFence,
    ) -> AccountFenceReceipt:
        """Public owned current-footprint/fence recheck; no replay or data transfer."""
        return self._recheck(connection, snapshot, fence)

    def recheck_snapshot_after_continuous_publication_in_transaction(
        self,
        connection: Connection,
        snapshot: ResolvedDailyRuntimeSnapshot,
        *,
        fence: AccountFence,
        prepared_account: object,
        account_receipt: object,
    ) -> AccountFenceReceipt:
        """Recheck unchanged B and exactly one actual pending C append.

        The caller requires the full original B graph outside SQL. Original
        source owners authenticate their historical inputs and the exact C
        publication pair; this helper never resolves, writes or grants delivery.
        With no captured C dependency, the ordinary full B recheck is sufficient
        and the enclosing publisher remains responsible for its C pair.
        """
        from packages.domain.continuous_persistence_contracts import ContinuousAccountReceipt
        from packages.persistence.continuous_account import (
            PreparedContinuousCommit,
            SqlContinuousAccount,
        )

        self._connection(connection)
        self._resolved(snapshot)
        raw = snapshot.raw
        if fence != raw.receipt.fence:
            raise DailyRuntimeRiskConflict("unchanged publication fence differs")
        all_tables = (
            *raw.tables,
            *raw.producer.tables,
            *(() if raw.attempt_sources is None else raw.attempt_sources.tables),
            *(() if raw.observed_sources is None else raw.observed_sources.tables),
        )
        c_tables = tuple(item for item in all_tables if item.table is continuous_account_commits)
        if not c_tables:
            return self._recheck(connection, snapshot, fence)
        accounts = getattr(self.producers, "accounts", None)
        if (
            len(c_tables) != 1
            or type(accounts) is not SqlContinuousAccount
            or accounts.engine is not self.engine
            or accounts.coordinator is not self.coordinator
            or type(prepared_account) is not PreparedContinuousCommit
            or type(account_receipt) is not ContinuousAccountReceipt
        ):
            raise DailyRuntimeRiskConflict("unchanged publication requires the exact C owner pair")
        lock_account_capacity_serialization(connection, raw.account_id)
        self._no_legacy(connection, raw.account_id)
        current = accounts.require_committed_in_transaction(
            connection, prepared=prepared_account, receipt=account_receipt
        )
        (original_c,) = c_tables
        previous = prepared_account.previous
        if (
            current.scope.account_id != raw.account_id
            or original_c.account_id != raw.account_id
            or len(original_c.rows) + 1 > MAX_ROWS
            or any(row["command_id"] == current.row["command_id"] for row in original_c.rows)
            or (previous is None and (original_c.rows or current.row["sequence"] != 1))
            or (
                previous is not None
                and (
                    not original_c.rows
                    or max(original_c.rows, key=lambda row: row["sequence"])
                    != previous.snapshot.row
                    or current.row["sequence"] != previous.receipt.commit.sequence + 1
                    or current.row["previous_commit_sha256"]
                    != previous.snapshot.row["commit_sha256"]
                )
            )
        ):
            raise DailyRuntimeRiskConflict("unchanged publication original C prefix differs")
        budget = self._continued_budget(raw)
        budget.charge(1, *self._row_sizes(continuous_account_commits, current.row))
        for captured in all_tables:
            if captured is original_c:
                _recheck_table(
                    connection,
                    RuntimeTableSnapshot(
                        continuous_account_commits,
                        raw.account_id,
                        (*original_c.rows, current.row),
                    ),
                )
            else:
                _recheck_table(connection, captured)
        if raw.producer.tables:
            self.producers.recheck_in_transaction(connection, raw.producer)
        for raw_source, resolved_source, reader, method in (
            (
                raw.attempt_sources,
                snapshot.attempt_sources,
                None if raw.attempt_sources is None else self._attempt_reader(),
                "recheck_attempt_sources_after_publication_in_transaction",
            ),
            (
                raw.observed_sources,
                snapshot.observed_sources,
                None if raw.observed_sources is None else self._observed_reader(),
                "recheck_observed_hold_sources_after_publication_in_transaction",
            ),
        ):
            if raw_source is None:
                continue
            if resolved_source is None or resolved_source.snapshot is not raw_source:
                raise DailyRuntimeRiskConflict("unchanged publication source preparation differs")
            recheck = getattr(reader, method, None)
            if not callable(recheck):
                raise DailyRuntimeRiskConflict("unchanged publication exact source reader missing")
            recheck(
                connection,
                resolved_source,
                prepared_account=prepared_account,
                account_receipt=account_receipt,
            )
        # Recheck actual pending C and the actual clock after every source read.
        accounts.require_committed_in_transaction(
            connection, prepared=prepared_account, receipt=account_receipt
        )
        receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        if receipt.validated_at < raw.receipt.validated_at:
            raise DailyRuntimeRiskConflict("unchanged publication clock regressed")
        return receipt

    def _bindings(self, record: _AdmissionRecord) -> tuple[RuntimeCommitmentBinding, ...]:
        return tuple(
            RuntimeCommitmentBinding(
                account_id=record.admission.evidence.assignment.account_id,
                commitment=item,
                origin="daily_runtime",
                source_id=content_digest(
                    (
                        "daily-admission/1",
                        record.admission.evidence.assignment.account_id,
                        record.command_id,
                    )
                )
                + ":"
                + item.intent_id,
                source_sha256=record.semantic_sha256,
                original_policy_sha256=item.policy_sha256,
                projection=PROJECTION_PIN,
            )
            for item in record.prepared_commitments
        )

    def recheck_admission_publication_rows_in_transaction(
        self,
        connection: Connection,
        admission: PreparedDailyAdmission,
        *,
        prepared_account: object,
        account_receipt: object,
        fence: AccountFence,
    ) -> None:
        """Prove complete original rows plus only this owned admission and C append.

        This SQL-only proof is shared with the concrete source owner. It grants
        no new risk authority and performs no source callback or financial replay.
        """
        from packages.domain.continuous_persistence_contracts import ContinuousAccountReceipt
        from packages.persistence.continuous_account import (
            PreparedContinuousCommit,
            SqlContinuousAccount,
        )
        from packages.persistence.continuous_composition import SqlContinuousCommitComposer

        self.require_prepared_admission_in_transaction(connection, admission)
        accounts = getattr(self.producers, "accounts", None)
        if (
            type(accounts) is not SqlContinuousAccount
            or accounts.engine is not self.engine
            or accounts.coordinator is not self.coordinator
            or type(accounts.composer) is not SqlContinuousCommitComposer
            or accounts.composer.daily is not self
            or accounts.composer.producer_history is not self.producers
            or type(prepared_account) is not PreparedContinuousCommit
            or type(account_receipt) is not ContinuousAccountReceipt
            or admission.retry
            or fence != admission.snapshot.raw.receipt.fence
        ):
            raise DailyRuntimeRiskConflict("admission publication requires exact actual owners")
        original_current = accounts.composer.require_frontier_admission_in_transaction(
            connection, prepared_account, admission
        )
        self.require_resolved_snapshot(original_current)
        if original_current.raw.receipt.fence != fence:
            raise DailyRuntimeRiskConflict("admission publication original current fence differs")
        lock_account_capacity_serialization(connection, admission.snapshot.raw.account_id)
        self._no_legacy(connection, admission.snapshot.raw.account_id)
        current = accounts.require_committed_in_transaction(
            connection, prepared=prepared_account, receipt=account_receipt
        )
        previous = prepared_account.previous
        if (
            previous is None
            or current.scope.account_id != admission.snapshot.raw.account_id
            or current.row["sequence"] != previous.receipt.commit.sequence + 1
            or current.row["previous_commit_sha256"] != previous.snapshot.row["commit_sha256"]
        ):
            raise DailyRuntimeRiskConflict("admission publication actual predecessor differs")
        original_head = {c.name: previous.snapshot.row[c.name] for c in continuous_account_heads.c}
        current_head = {c.name: current.row[c.name] for c in continuous_account_heads.c}
        for snapshot in (admission.snapshot, original_current):
            raw = snapshot.raw
            if raw.account_id != current.scope.account_id:
                raise DailyRuntimeRiskConflict("admission publication snapshot account differs")
            self._recheck_publication_rows(connection, raw, admission.writes, ())
            budget = self._continued_budget(raw)
            for write in admission.writes:
                budget.charge(1, *self._row_sizes(write.table, write.values))
            all_tables = (
                *raw.producer.tables,
                *(() if raw.attempt_sources is None else raw.attempt_sources.tables),
                *(() if raw.observed_sources is None else raw.observed_sources.tables),
            )
            seen: set[sa.Table] = set()
            for captured in all_tables:
                if captured.table in seen or captured.account_id != raw.account_id:
                    raise DailyRuntimeRiskConflict("admission source table inventory differs")
                seen.add(captured.table)
                rows = captured.rows
                if captured.table is continuous_account_commits:
                    if (
                        not rows
                        or max(rows, key=lambda row: row["sequence"]) != previous.snapshot.row
                        or any(row["command_id"] == current.row["command_id"] for row in rows)
                    ):
                        raise DailyRuntimeRiskConflict("admission original C prefix differs")
                    rows = (*rows, current.row)
                    budget.charge(1, *self._row_sizes(continuous_account_commits, current.row))
                elif captured.table is continuous_account_heads:
                    if rows != (original_head,):
                        raise DailyRuntimeRiskConflict("admission original C head differs")
                    rows = (current_head,)
                    old_payload, old_metadata = self._row_sizes(captured.table, original_head)
                    new_payload, new_metadata = self._row_sizes(captured.table, current_head)
                    budget.charge(
                        0, max(0, new_payload - old_payload), max(0, new_metadata - old_metadata)
                    )
                else:
                    rows = (
                        *rows,
                        *(w.values for w in admission.writes if w.table is captured.table),
                    )
                if len(rows) > MAX_ROWS:
                    raise DailyRuntimeRiskConflict("admission publication row bound exceeded")
                _recheck_table(
                    connection, RuntimeTableSnapshot(captured.table, captured.account_id, rows)
                )
            if snapshot is admission.snapshot and not {
                continuous_account_commits,
                continuous_account_heads,
            }.issubset(seen):
                raise DailyRuntimeRiskConflict("admission original full C capture required")

    def recheck_admission_publication_in_transaction(
        self,
        connection: Connection,
        admission: PreparedDailyAdmission,
        *,
        prepared_account: object,
        account_receipt: object,
        fence: AccountFence,
    ) -> RuntimeRiskAdmission:
        """Authenticate original sources and the exact paired poststate before COMMIT."""
        self.recheck_admission_publication_rows_in_transaction(
            connection,
            admission,
            prepared_account=prepared_account,
            account_receipt=account_receipt,
            fence=fence,
        )
        recheck = getattr(
            self.producers, "recheck_admission_sources_after_publication_in_transaction", None
        )
        if not callable(recheck):
            raise DailyRuntimeRiskConflict("exact admission publication source owner required")
        recheck(
            connection,
            admission.snapshot.raw.producer,
            admission=admission,
            prepared_account=prepared_account,
            account_receipt=account_receipt,
            fence=fence,
        )
        snapshot = admission.snapshot
        raw = snapshot.raw
        for raw_source, resolved_source, reader, method in (
            (
                raw.attempt_sources,
                snapshot.attempt_sources,
                None if raw.attempt_sources is None else self._attempt_reader(),
                "recheck_attempt_sources_after_publication_in_transaction",
            ),
            (
                raw.observed_sources,
                snapshot.observed_sources,
                None if raw.observed_sources is None else self._observed_reader(),
                "recheck_observed_hold_sources_after_publication_in_transaction",
            ),
        ):
            if raw_source is None:
                continue
            if resolved_source is None or resolved_source.snapshot is not raw_source:
                raise DailyRuntimeRiskConflict("admission publication original source differs")
            callback = getattr(reader, method, None)
            if not callable(callback):
                raise DailyRuntimeRiskConflict("admission publication source reader missing")
            callback(
                connection,
                resolved_source,
                prepared_account=prepared_account,
                account_receipt=account_receipt,
            )
        self.recheck_admission_publication_rows_in_transaction(
            connection,
            admission,
            prepared_account=prepared_account,
            account_receipt=account_receipt,
            fence=fence,
        )
        receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        if (
            receipt.validated_at < raw.receipt.validated_at
            or admission.valid_until is None
            or receipt.validated_at >= admission.valid_until
        ):
            raise DailyRuntimeRiskConflict("admission publication original deadline expired")
        final_clock = getattr(self.producers, "require_current_admission_clock", None)
        if not callable(final_clock):
            raise DailyRuntimeRiskConflict("original admission final clock owner required")
        final_clock(raw.producer)
        return admission.result

    def _prepare(
        self,
        resolved: ResolvedRuntimeRiskInputs,
        batch: DailyIntentBatch,
        decision: DailyRiskDecision,
        risk_policy: DailyRiskPolicy,
    ) -> tuple[Commitment, ...]:
        if type(decision) is not DailyRiskDecision:
            raise DailyRuntimeRiskConflict("exact daily decision required")
        if resolved.context.point.knowledge_at != batch.target.trigger.as_of:
            raise DailyRuntimeRiskConflict("installation context differs from decision frontier")
        prepared = prepare_daily_commitments(
            state=resolved.state,
            snapshot=resolved.snapshot,
            batch=batch,
            decision=decision,
            context=resolved.context,
            execution_policy=resolved.execution_policy,
            risk_policy=risk_policy,
            accounting=self.accounting,
            attempt_namespace="daily-runtime-attempt",
        )
        if prepared.disposition not in ("installed", "no_intents"):
            raise DailyRuntimeRiskConflict("canonical commitment preparation was not applied")
        return prepared.commitments

    def _hold_writes(self, record: _AdmissionRecord) -> tuple[_Write, ...]:
        account = record.admission.evidence.assignment.account_id
        identifier = content_digest(("daily-admission/1", account, record.command_id))
        writes = []
        for binding in self._bindings(record):
            item = binding.commitment
            writes.append(
                _Write(
                    hold_events,
                    MappingProxyType(
                        dict(
                            hold_id=item.commitment_id,
                            revision=1,
                            account_id=account,
                            admission_id=identifier,
                            intent_id=item.intent_id,
                            execution_session=item.execution_session,
                            previous_sha256=None,
                            **self._encode(binding),
                        )
                    ),
                )
            )
            writes.append(
                _Write(
                    hold_heads,
                    MappingProxyType(
                        dict(
                            hold_id=item.commitment_id,
                            account_id=account,
                            revision=1,
                            semantic_sha256=binding.semantic_sha256,
                        )
                    ),
                )
            )
            pending_hash = content_digest(("pending-daily-intent/1", item, identifier))
            outbound_id = content_digest(("daily-outbound/1", identifier, item.intent_id))
            writes.append(
                _Write(
                    outbound,
                    MappingProxyType(
                        dict(
                            outbound_id=outbound_id,
                            account_id=account,
                            admission_id=identifier,
                            intent_id=item.intent_id,
                            hold_id=item.commitment_id,
                            request_sha256=pending_hash,
                            binding_sha256=content_digest(
                                (outbound_id, binding.semantic_sha256, pending_hash)
                            ),
                        )
                    ),
                )
            )
        return tuple(writes)

    def prepare_admission(
        self,
        snapshot: ResolvedDailyRuntimeSnapshot,
        *,
        command_id: str,
        request_sha256: str,
        batch: DailyIntentBatch,
        assignment_sha256: str,
        input_refs: RuntimeRiskInputRefs,
        prepared_commitments: tuple[Commitment, ...],
    ) -> PreparedDailyAdmission:
        self._resolved(snapshot)
        require_identifier(command_id, "command")
        require_digest(request_sha256, "request")
        require_digest(assignment_sha256, "assignment")
        raw = snapshot.raw
        if (
            raw.command_id != command_id
            or raw.input_refs != input_refs
            or raw.owner_command_ref is not None
        ):
            raise DailyRuntimeRiskConflict("prepared admission selection differs")
        prior = next(
            (record for record in snapshot.admissions if record.command_id == command_id), None
        )
        if prior is not None:
            if (
                prior.request_sha256,
                prior.admission.decision.batch,
                prior.admission.evidence.assignment.semantic_sha256,
                prior.prepared_commitments,
                prior.resolved.inputs,
            ) != (request_sha256, batch, assignment_sha256, prepared_commitments, input_refs):
                raise DailyRuntimeRiskConflict("immutable admission retry conflicts")
            return self._own(
                PreparedDailyAdmission(snapshot, prior.admission, (), None, True, self._seal)
            )
        assignment = snapshot.assignment
        if assignment is None or assignment.semantic_sha256 != assignment_sha256:
            raise DailyRuntimeRiskConflict("current assignment differs")
        if input_refs.phase != "decision":
            raise DailyRuntimeRiskConflict("activation belongs to the separate attempt bridge")
        resolved = self.producers.resolve(
            raw.producer,
            assignment=assignment,
            previous=None,
            refs=input_refs,
            owner_command_ref=None,
            fence_receipt=raw.receipt,
            control=snapshot.control,
        )
        if type(resolved) is not ResolvedRuntimeRiskInputs or resolved.inputs != input_refs:
            raise DailyRuntimeRiskConflict("resolved current input references differ")
        if input_refs.obligations != snapshot.obligations:
            raise DailyRuntimeRiskConflict("resolved full obligation inventory differs")
        self._heads(snapshot, input_refs.heads)
        accepted = tuple(
            sorted(
                binding.commitment.intent_id
                for binding in snapshot.obligations.bindings
                if binding.commitment.execution_session == input_refs.execution_session
            )
        )
        if accepted != input_refs.accepted_intent_ids:
            raise DailyRuntimeRiskConflict("durable accepted-intent registry differs")
        controls = next(
            (source for source in input_refs.sources if source.spec.role == "controls"), None
        )
        if (
            (
                snapshot.control is None
                or snapshot.control.effective_state != OperationalControlState.RUNNING
            )
            and controls is not None
            and controls.status == "available"
        ):
            raise DailyRuntimeRiskConflict("producer incorrectly marked durable controls available")
        from packages.domain.daily_runtime_risk import build_daily_runtime_evidence

        at = batch.target.trigger.as_of
        if (
            resolved.snapshot.point.knowledge_at != at
            or resolved.context.point.knowledge_at != at
            or raw.receipt.validated_at < at
        ):
            raise DailyRuntimeRiskConflict("original decision frontier and capture time differ")
        fact = build_daily_runtime_evidence(
            assignment,
            resolved.snapshot,
            batch,
            input_refs,
            producer_map=resolved.producer_map,
            evaluated_at=at,
        )
        decision = evaluate_daily_risk(assignment.policy, resolved.snapshot, batch, fact, at)
        expected = (
            self._prepare(resolved, batch, decision, assignment.policy) if decision.approved else ()
        )
        if type(prepared_commitments) is not tuple or prepared_commitments != expected:
            raise DailyRuntimeRiskConflict("prospective canonical commitments differ")
        expiry = min(
            datetime.combine(
                input_refs.execution_session, time(9), ZoneInfo("America/New_York")
            ).astimezone(UTC),
            batch.target.expires_at,
            raw.receipt.valid_until,
            resolved.snapshot.point.knowledge_at + timedelta(seconds=5),
            *(source.valid_until for source in input_refs.sources),
        )
        for source in input_refs.sources:
            if source.spec.role == "clock":
                expiry = min(expiry, source.source_at + timedelta(seconds=30))
        if input_refs.reconciliation is not None:
            expiry = min(
                expiry,
                input_refs.reconciliation.observation_started_at + timedelta(seconds=60),
                input_refs.reconciliation.completed_at + timedelta(seconds=60),
                input_refs.reconciliation.observation_received_through + timedelta(seconds=60),
            )
        if raw.receipt.validated_at >= expiry:
            raise DailyRuntimeRiskConflict("admission expired before commit")
        result = RuntimeRiskAdmission(
            evidence=fact,
            decision=decision,
            recorded_at=raw.receipt.validated_at,
            expires_at=expiry,
        )
        record = _AdmissionRecord(command_id, request_sha256, result, resolved, expected)
        identifier = content_digest(("daily-admission/1", raw.account_id, command_id))
        row = MappingProxyType(
            dict(
                admission_id=identifier,
                account_id=raw.account_id,
                command_id=command_id,
                request_sha256=request_sha256,
                batch_sha256=batch.semantic_sha256,
                assignment_generation=assignment.generation,
                assignment_sha256=assignment_sha256,
                approved=decision.approved,
                **self._encode(record),
            )
        )
        return self._own(
            PreparedDailyAdmission(
                snapshot,
                result,
                (_Write(admissions, row), *self._hold_writes(record)),
                expiry,
                False,
                self._seal,
            )
        )

    def prepare_assignment(
        self,
        snapshot: ResolvedDailyRuntimeSnapshot,
        *,
        assignment: RuntimeRiskAssignment,
        expected_previous_sha256: str | None,
        owner_command_ref: JournalReceipt,
    ) -> PreparedDailyAssignment:
        self._resolved(snapshot)
        raw, current = snapshot.raw, snapshot.assignment
        if (
            raw.account_id != assignment.account_id
            or raw.owner_command_ref != owner_command_ref
            or raw.input_refs is not None
        ):
            raise DailyRuntimeRiskConflict("prepared owner selection differs")
        retry = current == assignment
        previous = (
            (snapshot.assignment_rows[-2] if len(snapshot.assignment_rows) > 1 else None)
            if retry
            else current
        )
        if (
            expected_previous_sha256 != (None if previous is None else previous.semantic_sha256)
            or assignment.previous_assignment_sha256 != expected_previous_sha256
            or assignment.generation != (1 if previous is None else previous.generation + 1)
        ):
            raise DailyRuntimeRiskConflict("assignment transition predecessor differs")
        if previous is None and assignment.enabled_for_new_exposure:
            raise DailyRuntimeRiskConflict("initial assignment must be disabled")
        if (
            previous is not None
            and previous.account_binding_sha256 != assignment.account_binding_sha256
        ):
            raise DailyRuntimeRiskConflict("policy cutover cannot replace account identity")
        verified = self.producers.resolve(
            raw.producer,
            assignment=assignment,
            previous=previous,
            refs=None,
            owner_command_ref=owner_command_ref,
            fence_receipt=raw.receipt,
            control=snapshot.control,
        )
        if type(verified) is not VerifiedRuntimeAssignmentCommand:
            raise DailyRuntimeRiskConflict("exact verified owner command required")
        command = verified.command
        if (
            command.account_id,
            command.before_assignment_sha256,
            command.after_assignment_sha256,
            command.command_id,
            command.semantic_sha256,
        ) != (
            assignment.account_id,
            expected_previous_sha256,
            assignment.semantic_sha256,
            owner_command_ref.command_id,
            owner_command_ref.command_sha256,
        ):
            raise DailyRuntimeRiskConflict("owner command assignment scope differs")
        at = raw.receipt.validated_at
        if (
            not command.requested_at <= at < command.expires_at
            or command.expected_heads != verified.current_heads
        ):
            raise DailyRuntimeRiskConflict("owner command is expired or current heads changed")
        self._heads(snapshot, verified.current_heads)
        expiry = min(command.expires_at, raw.receipt.valid_until)
        if assignment.enabled_for_new_exposure:
            result = verified.reconciliation
            if (
                result is None
                or result.status != "converged"
                or result.heads != verified.current_heads
                or result.scope.account_id != assignment.account_id
                or result.scope.binding_sha256 != assignment.account_binding_sha256
                or result.scope.environment != "stateful_simulation"
                or result.policy_sha256 != ReconciliationPolicy().semantic_sha256
                or not timedelta(0) <= at - result.observation_started_at < timedelta(seconds=60)
                or not timedelta(0) <= at - result.completed_at < timedelta(seconds=60)
                or not timedelta(0)
                <= at - result.observation_received_through
                < timedelta(seconds=60)
            ):
                raise DailyRuntimeRiskConflict(
                    "enabling transition requires fresh exact reconciliation"
                )
            expiry = min(
                expiry,
                result.observation_started_at + timedelta(seconds=60),
                result.completed_at + timedelta(seconds=60),
                result.observation_received_through + timedelta(seconds=60),
            )
        rows = next(table.rows for table in raw.tables if table.table is assignments)
        if retry and (rows[-1]["command_id"], rows[-1]["command_sha256"]) != (
            command.command_id,
            command.semantic_sha256,
        ):
            raise DailyRuntimeRiskConflict("assignment retry command differs")
        writes = (
            ()
            if retry
            else (
                _Write(
                    assignments,
                    MappingProxyType(
                        dict(
                            account_id=assignment.account_id,
                            generation=assignment.generation,
                            command_id=command.command_id,
                            command_sha256=command.semantic_sha256,
                            command_payload=self.codec.encode_record(command),
                            recorded_at=at,
                            previous_sha256=expected_previous_sha256,
                            **self._encode(assignment),
                        )
                    ),
                ),
            )
        )
        if writes and len(writes[0].values["command_payload"]) > MAX_BYTES:
            raise DailyRuntimeRiskConflict("owner command exceeds its byte bound")
        head = MappingProxyType(
            dict(
                account_id=assignment.account_id,
                generation=assignment.generation,
                semantic_sha256=assignment.semantic_sha256,
            )
        )
        return self._own(
            PreparedDailyAssignment(snapshot, assignment, writes, head, expiry, retry, self._seal)
        )

    def _recheck(
        self, connection: Connection, snapshot: ResolvedDailyRuntimeSnapshot, fence: AccountFence
    ) -> AccountFenceReceipt:
        self._connection(connection)
        self._resolved(snapshot)
        if snapshot.seal is not self._seal or fence != snapshot.raw.receipt.fence:
            raise DailyRuntimeRiskConflict("prepared snapshot/fence differs")
        lock_account_capacity_serialization(connection, snapshot.raw.account_id)
        receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        self._no_legacy(connection, snapshot.raw.account_id)
        for table in (*snapshot.raw.tables, *snapshot.raw.producer.tables):
            _recheck_table(connection, table)
        if snapshot.raw.producer.tables:
            self.producers.recheck_in_transaction(connection, snapshot.raw.producer)
        if snapshot.raw.attempt_sources is not None:
            if (
                snapshot.attempt_sources is None
                or snapshot.attempt_sources.snapshot is not snapshot.raw.attempt_sources
            ):
                raise DailyRuntimeRiskConflict("attempt source preparation is incomplete")
            for table in snapshot.raw.attempt_sources.tables:
                _recheck_table(connection, table)
            self._attempt_reader().recheck_attempt_sources_in_transaction(
                connection, snapshot.attempt_sources
            )
        if snapshot.raw.observed_sources is not None:
            if (
                snapshot.observed_sources is None
                or snapshot.observed_sources.snapshot is not snapshot.raw.observed_sources
            ):
                raise DailyRuntimeRiskConflict("observed source preparation is incomplete")
            for table in snapshot.raw.observed_sources.tables:
                _recheck_table(connection, table)
            self._observed_reader().recheck_observed_hold_sources_in_transaction(
                connection, snapshot.observed_sources
            )
        if receipt.validated_at < snapshot.raw.receipt.validated_at:
            raise DailyRuntimeRiskConflict("prepared clock regressed")
        return receipt

    def admit_prepared_in_transaction(
        self, connection: Connection, prepared: PreparedDailyAdmission, *, fence: AccountFence
    ) -> RuntimeRiskAdmission:
        self._connection(connection)
        self._require_prepared_admission(prepared)
        with connection.begin_nested():
            receipt = self._recheck(connection, prepared.snapshot, fence)
            if prepared.valid_until is not None and receipt.validated_at >= prepared.valid_until:
                raise DailyRuntimeRiskConflict("admission expired before commit")
            for write in prepared.writes:
                connection.execute(sa.insert(write.table).values(**write.values))
            receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
            if prepared.valid_until is not None and receipt.validated_at >= prepared.valid_until:
                raise DailyRuntimeRiskConflict("admission expired before commit")
            return prepared.result

    def install_prepared_in_transaction(
        self, connection: Connection, prepared: PreparedDailyAssignment, *, fence: AccountFence
    ) -> RuntimeRiskAssignment:
        self._connection(connection)
        self._require_prepared_assignment(prepared)
        with connection.begin_nested():
            receipt = self._recheck(connection, prepared.snapshot, fence)
            if receipt.validated_at >= prepared.valid_until:
                raise DailyRuntimeRiskConflict("assignment evidence expired before commit")
            for write in prepared.writes:
                connection.execute(sa.insert(write.table).values(**write.values))
            current = prepared.snapshot.assignment
            if not prepared.retry:
                if current is None:
                    connection.execute(sa.insert(assignment_heads).values(**prepared.head_values))
                else:
                    changed = connection.execute(
                        sa.update(assignment_heads)
                        .where(
                            assignment_heads.c.account_id == current.account_id,
                            assignment_heads.c.generation == current.generation,
                            assignment_heads.c.semantic_sha256 == current.semantic_sha256,
                        )
                        .values(**prepared.head_values)
                        .returning(assignment_heads.c.account_id)
                    ).scalar_one_or_none()
                    if changed != current.account_id:
                        raise DailyRuntimeRiskConflict("assignment CAS failed")
            receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
            if receipt.validated_at >= prepared.valid_until:
                raise DailyRuntimeRiskConflict("assignment evidence expired before commit")
            return prepared.result

    def recheck_installed_assignment_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedDailyAssignment,
        *,
        fence: AccountFence,
    ) -> RuntimeRiskAssignment:
        """Check exact assignment-only poststate and its actual original owner source."""
        self._connection(connection)
        self._require_prepared_assignment(prepared)
        raw = prepared.snapshot.raw
        if fence != raw.receipt.fence:
            raise DailyRuntimeRiskConflict("assignment publication fence differs")
        lock_account_capacity_serialization(connection, raw.account_id)
        self._no_legacy(connection, raw.account_id)
        prior_heads = next(item.rows for item in raw.tables if item.table is assignment_heads)
        updates = (
            ()
            if prepared.retry
            else (
                _HeadUpdate(
                    assignment_heads,
                    None if not prior_heads else prior_heads[0],
                    prepared.head_values,
                ),
            )
        )
        self._recheck_publication_rows(connection, raw, prepared.writes, updates)
        recheck = getattr(self.producers, "recheck_installed_owner_sources_in_transaction", None)
        if raw.owner_command_ref is None or not callable(recheck):
            raise DailyRuntimeRiskConflict(
                "assignment publication requires its actual owner source"
            )
        recheck(connection, prepared=prepared, fence=fence)
        receipt = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        if receipt.validated_at >= prepared.valid_until:
            raise DailyRuntimeRiskConflict("assignment publication deadline expired")
        return prepared.result
