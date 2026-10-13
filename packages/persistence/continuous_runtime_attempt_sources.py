"""Authenticate internal attempt sources through actual retained account provenance.

Source-only records contain no future action/envelope/parent hash. Fresh sources
need this instance's owned C/B preparation; historical reads authenticate original
C metadata and immutable source rows before B's canonical financial history replay.
No source reference confers delivery authority.
"""

import sys
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field, fields, replace
from datetime import datetime
from enum import EnumType
from hashlib import sha256
from threading import current_thread
from types import FunctionType, ModuleType
from typing import Any, TypeVar, cast
from weakref import WeakValueDictionary, finalize
from weakref import ref as _weakref

import sqlalchemy as sa
from sqlalchemy import Connection, Engine

from packages.application.causal_engine import (
    continuous_runtime_action_context,
    continuous_runtime_loss_inputs,
)
from packages.application.continuous_account_transition import ContinuousAccountTransitionPreparer
from packages.application.daily_runtime_activation import prepare_daily_runtime_activation
from packages.domain.accounting_contracts import (
    AccountingCommand,
    ActivateRuntimeCommitments,
    ReleaseRuntimeUnsent,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import ContinuousEngineInputs
from packages.domain.continuous_persistence_contracts import (
    CONTINUOUS_RUNTIME_ACTION_SCHEMA,
    ContinuousAccountReceipt,
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.continuous_runtime_action import ContinuousRuntimeAction
from packages.domain.continuous_runtime_attempt_contracts import (
    RUNTIME_ATTEMPT_CLOSURE_SCHEMA,
    RUNTIME_ATTEMPT_SOURCE_SCHEMA,
    ContinuousRuntimeAttemptClosure,
)
from packages.domain.continuous_runtime_source_contracts import (
    RUNTIME_SOURCE_SCHEMA,
    ContinuousRuntimeSourceDescriptor,
)
from packages.domain.daily_attempt import (
    daily_fence_reference,
    prepare_daily_activation,
    prepare_daily_attempt,
    prepare_daily_dispatch,
    reduce_daily_attempt,
)
from packages.domain.daily_attempt_contracts import (
    CanonicalDailyAttempt,
    DailyAttemptEnvelope,
    DailyAttemptEvent,
    DailyAttemptPreparation,
    DailyDispatchClaim,
    DailyDispatchRecord,
    DailyUnsentProof,
    DailyVenueSubmissionRequest,
)
from packages.domain.daily_observed_hold_contracts import (
    DailyObservedHoldGroup,
    daily_runtime_effect_watermark,
)
from packages.domain.daily_risk import evaluate_daily_risk
from packages.domain.daily_runtime_contracts import (
    RuntimeObligationInventory,
    RuntimeRiskAssignment,
)
from packages.domain.durable_journal_contracts import (
    MAX_SEQUENCE,
    JournalAppend,
    JournalHead,
    JournalKey,
    JournalReceipt,
    JournalRecord,
    empty_head,
    journal_identifier,
)
from packages.domain.identifiers import canonical_id
from packages.domain.operational_control import OperationalControlTransition
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.research_job_contracts import (
    ObjectRef,
    ResearchArtifactStore,
    ResearchRecordCodec,
)
from packages.domain.stateful_venue_contracts import VenueSourceReference
from packages.domain.submission_attempt import SubmissionAttemptState
from packages.persistence import _factory_attempt_fingerprint as _factory_data
from packages.persistence._factory_attempt_behavior import (
    _AttemptBehaviorChanged,
    _AttemptBehaviorUnsupported,
    _capture_attempt_behavior,
)
from packages.persistence.continuous_account import (
    ContinuousReferenceSnapshot,
    PreparedContinuousCommit,
    ResolvedContinuousAccount,
    ResolvedContinuousReference,
    SqlContinuousAccount,
)
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.continuous_runtime_sources import (
    ResolvedRuntimeDescriptor,
    SqlContinuousRuntimeSources,
)
from packages.persistence.daily_runtime_risk import (
    MAX_METADATA_BYTES,
    MAX_ROWS,
    ResolvedDailyRuntimeSnapshot,
    ResolvedRuntimeAttemptSources,
    RetainedDailyAdmission,
    RuntimeAssignmentCommand,
    RuntimeAttemptAccountingSource,
    RuntimeAttemptSourcePlan,
    RuntimeAttemptSourceSnapshot,
    RuntimeReadBudget,
    RuntimeTableSnapshot,
    SqlDailyRuntimeRisk,
    _recheck_table,
    _require_same_runtime_tables,
    _typed_rows,
    capture_runtime_table,
    daily_attempt_inventory_sha256,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_assignments,
    daily_runtime_attempt_events,
    daily_runtime_consumptions,
    daily_runtime_observed_hold_groups,
)
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
from packages.persistence.durable_journal import (
    _has_records as _journal_has_records,
)
from packages.persistence.durable_journal import (
    _ReceiptRows as _FactoryReceiptRows,
)
from packages.persistence.durable_journal import (
    _stream_row as _journal_stream_row,
)
from packages.persistence.operational_control import (
    _completion_rows_index,
    _verified_history_from_rows,
)
from packages.persistence.schema import (
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)

MAX_ATTEMPT_OBJECT_BYTES = 32 * 1024 * 1024
MAX_ATTEMPT_OBJECT_REFERENCES = 4096
CHECKPOINT_SCHEMA = "continuous-checkpoint/1"
T = TypeVar("T")


class ContinuousRuntimeAttemptSourceError(ValueError):
    """Static original-source, ownership or bounded provenance failure."""


class _Graph:
    def __init__(self, artifacts: ResearchArtifactStore, codec: ResearchRecordCodec) -> None:
        self.artifacts, self.codec = artifacts, codec
        self.refs: dict[str, ObjectRef] = {}
        self.payloads: dict[str, bytes] = {}
        self.values: dict[tuple[str, type[Any]], Any] = {}
        self.total = 0

    def admit(self, refs: tuple[ObjectRef, ...]) -> None:
        for reference in refs:
            reference.__post_init__()
            if reference.codec_version not in ("personal-record/1", "personal-provider-json/1"):
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_OBJECT_CODEC_UNSUPPORTED")
            old = self.refs.get(reference.object_sha256)
            if old is not None:
                if old != reference:
                    raise ContinuousRuntimeAttemptSourceError("ATTEMPT_OBJECT_IDENTITY_CONFLICT")
                continue
            self.total += reference.byte_count
            if (
                self.total > MAX_ATTEMPT_OBJECT_BYTES
                or len(self.refs) >= MAX_ATTEMPT_OBJECT_REFERENCES
            ):
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_COMPLETE_OBJECT_GRAPH_LIMIT")
            self.refs[reference.object_sha256] = reference

    def raw(self, reference: ObjectRef) -> bytes:
        if reference.codec_version != "personal-record/1":
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_TYPED_OBJECT_REQUIRED")
        self.admit((reference,))
        key = reference.object_sha256
        if key not in self.payloads:
            payload = self.artifacts.read(reference, max_bytes=reference.byte_count)
            if (
                type(payload) is not bytes
                or len(payload) != reference.byte_count
                or sha256(payload).hexdigest() != key
            ):
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_OBJECT_BYTES_DIFFER")
            self.payloads[key] = payload
        return self.payloads[key]

    def read(self, reference: ContinuousEvidenceRef, kind: type[Any], schema: str) -> Any:
        if (
            type(reference) is not ContinuousEvidenceRef
            or reference.schema_id != schema
            or reference.object_ref.codec_version != "personal-record/1"
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_OBJECT_SCHEMA_DIFFERS")
        self.admit((reference.object_ref,))
        key = (reference.object_ref.object_sha256, kind)
        if key not in self.values:
            raw = self.raw(reference.object_ref)
            value = self.codec.decode_record(raw, kind)
            if type(value) is not kind or self.codec.encode_record(value) != raw:
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_OBJECT_CODEC_DIFFERS")
            self.values[key] = value
        value = self.values[key]
        if value.semantic_sha256 != reference.semantic_sha256:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_OBJECT_CONTENT_DIFFERS")
        return value

    def encode(self, schema: str, value: ContractRecord) -> ContinuousEvidenceRef:
        payload = self.codec.encode_record(value)
        if type(payload) is not bytes or not payload:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_OBJECT_ENCODING_INVALID")
        reference = ObjectRef(sha256(payload).hexdigest(), len(payload))
        self.admit((reference,))
        self.payloads[reference.object_sha256] = payload
        return ContinuousEvidenceRef(schema, reference, value.semantic_sha256)

    def publish(self) -> None:
        for key, payload in self.payloads.items():
            if self.artifacts.put(payload) != self.refs[key]:
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_OBJECT_STORE_DIFFERS")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedContinuousRuntimeAttemptSource:
    reference: ContinuousEvidenceRef
    source: RuntimeAttemptAccountingSource
    closure: ContinuousRuntimeAttemptClosure
    action: ContinuousRuntimeAction
    envelopes: tuple[DailyAttemptEnvelope, ...]
    previous: ResolvedContinuousAccount
    current: ResolvedDailyRuntimeSnapshot
    admissions: tuple[RetainedDailyAdmission, ...]
    seal: object = field(repr=False, compare=False)
    descriptor: ResolvedRuntimeDescriptor | None = None
    dispatch_appends: tuple[PreparedJournalAppend, ...] = ()
    outcome: object | None = None


@dataclass(frozen=True, slots=True)
class _Source:
    reference: ContinuousEvidenceRef
    source: RuntimeAttemptAccountingSource
    closure: ContinuousRuntimeAttemptClosure
    checkpoint: CausalEngineCheckpoint
    action: ContinuousRuntimeAction
    request: ContinuousEvidenceRef
    dispatches: tuple[tuple[JournalKey, DailyDispatchRecord], ...]
    admission_payloads: tuple[bytes, ...]
    fresh: PreparedContinuousRuntimeAttemptSource | None
    descriptor_plan: object | None = None
    descriptor: ContinuousRuntimeSourceDescriptor | None = None
    unsent_key_payload: bytes | None = None
    outcome_plan: object | None = None


@dataclass(frozen=True, slots=True)
class _Plan:
    sources: tuple[_Source, ...]


@dataclass(frozen=True, slots=True)
class _Captured:
    plan: _Plan
    provenance: tuple[RuntimeTableSnapshot, ...]
    references: tuple[ContinuousReferenceSnapshot, ...]
    historical: tuple[bool, ...]
    dispatches: tuple[tuple[JournalReadSnapshot, ...], ...]
    descriptors: tuple[object | None, ...] = ()
    outcomes: tuple[object | None, ...] = ()


@dataclass(frozen=True, slots=True)
class _Resolved:
    captured: _Captured
    references: tuple[ResolvedContinuousReference, ...]
    dispatches: tuple[tuple[ResolvedJournalRead, ...], ...]
    selected: tuple[tuple[RuntimeTableSnapshot, tuple[Any, ...]], ...]
    descriptors: tuple[object | None, ...] = ()
    outcomes: tuple[object | None, ...] = ()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class OriginalContinuousRuntimeAttemptPrefix:
    """Staged original-row facts only; B's complete replay still owns financial validation."""

    reference: ResolvedContinuousReference
    checkpoint: CausalEngineCheckpoint
    source: RuntimeAttemptAccountingSource
    admissions: tuple[RetainedDailyAdmission, ...]
    obligations: RuntimeObligationInventory
    attempts: tuple[CanonicalDailyAttempt, ...]
    attempt_envelopes: tuple[DailyAttemptEnvelope, ...]
    observed_groups: tuple[DailyObservedHoldGroup, ...]
    assignment: RuntimeRiskAssignment
    control: OperationalControlTransition | None
    through_coordinator_sequence: int
    selected: tuple[tuple[RuntimeTableSnapshot, tuple[Any, ...]], ...]
    state: _Captured = field(repr=False, compare=False)
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedCommittedContinuousRuntimeAttemptSources:
    """Original published dependencies only; no successful-COMMIT or delivery authority."""

    original: ResolvedRuntimeAttemptSources
    publication: ResolvedContinuousReference
    seal: object = field(repr=False, compare=False)


class _FactoryAttemptFingerprint:
    """Opaque operation-owned identity; possession alone grants no authority."""

    __slots__ = ("__weakref__",)


@dataclass(frozen=True, slots=True)
class _FactoryFingerprintState:
    owner: Any
    context: Any
    thread: object
    value: ResolvedRuntimeAttemptSources
    fingerprint: str
    data: Any
    data_fields: tuple[object, ...]
    source_behavior: Any
    root_behavior: Any
    root_module: ModuleType


# Registry entries do not strongly retain proof, owner or factory context. A
# failed issuance never returns its token, so its weak callback releases the graph.
_FACTORY_ATTEMPT_PROOFS: dict[int, tuple[Any, _FactoryFingerprintState]] = {}
_FACTORY_FINGERPRINT_RUNTIME: dict[str, Any] = {}
_FACTORY_ROOT_CONTAINERS = 32
_FACTORY_ROOT_BINDINGS = 512
_FACTORY_SOURCE_CONTAINERS = 16
_FACTORY_SOURCE_BINDINGS = 256


def _factory_fingerprint_behaviors() -> tuple[Any, Any, ModuleType]:
    source = _FACTORY_FINGERPRINT_RUNTIME.get("source")
    root = _FACTORY_FINGERPRINT_RUNTIME.get("root")
    module = _FACTORY_FINGERPRINT_RUNTIME.get("module")
    if source is None or root is None or module is None:
        raise _AttemptBehaviorUnsupported("ATTEMPT_FACTORY_RUNTIME_UNSUPPORTED")
    source.require()
    root.require()
    return source, root, module


def _factory_fingerprint_data_fields(data: Any) -> tuple[object, ...]:
    mapping = data.mapping
    return (
        data.records,
        data.runtime,
        mapping,
        data.containers,
        data.bindings,
        mapping.state,
        mapping.caches,
        mapping.positive,
        mapping.negative,
        mapping.token,
        mapping.max_members,
    )


def _factory_fingerprint_methods(source: object) -> None:
    if type(source) is not SqlContinuousRuntimeAttemptSources:
        raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FACTORY_ORIGINAL_OWNER_REQUIRED")
    namespace = object.__getattribute__(source, "__dict__")
    if (
        type(namespace) is not dict
        or len(namespace) > _FACTORY_SOURCE_BINDINGS // 4
        or any(type(name) is not str for name in namespace)
        or any(name in namespace for name in _FACTORY_SOURCE_METHODS)
    ):
        raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FACTORY_ORIGINAL_METHODS_REQUIRED")


def _register_factory_fingerprint_runtime(
    module: ModuleType, originals: tuple[tuple[Any, ...], ...]
) -> None:
    """One import-completion baseline; never first-use or caller-supplied authority."""
    if (
        type(module) is not ModuleType
        or module.__name__ != "packages.persistence.continuous_integrity"
        or "root" in _FACTORY_FINGERPRINT_RUNTIME
        or type(originals) is not tuple
        or not originals
        or any(
            type(entry) is not tuple
            or len(entry) != 4
            or type(entry[0]) is not FunctionType
            or entry[0].__code__ is not entry[1]
            or entry[0].__defaults__ is not entry[2]
            or entry[0].__kwdefaults__ is not entry[3]
            for entry in originals
        )
    ):
        raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FACTORY_ORIGINAL_RUNTIME_REQUIRED")
    try:
        behavior = _capture_attempt_behavior(
            functions=tuple(entry[0] for entry in originals),
            modules=(module,),
            classes=(
                module.SqlContinuousIntegrityReader,
                module.SqlContinuousCommitComposer,
                module._FactoryFingerprintContext,
                module._FactoryFingerprintUse,
                module._FactoryFingerprintOwner,
            ),
        )
        behavior.require()
    except _AttemptBehaviorUnsupported:
        behavior = None
    _FACTORY_FINGERPRINT_RUNTIME["module"] = module
    _FACTORY_FINGERPRINT_RUNTIME["root"] = behavior
    for name in ("_fail_factory_fingerprint_use", "_retire_factory_fingerprint_context"):
        callback = vars(module)[name]
        _FACTORY_FINGERPRINT_RUNTIME[name] = (callback, callback.__code__)


class SqlContinuousRuntimeAttemptSources:
    def __init__(
        self,
        engine: Engine,
        *,
        accounts: SqlContinuousAccount,
        preparer: ContinuousAccountTransitionPreparer,
        daily: SqlDailyRuntimeRisk,
        runtime_sources: SqlContinuousRuntimeSources,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
    ) -> None:
        if (
            type(accounts) is not SqlContinuousAccount
            or type(preparer) is not ContinuousAccountTransitionPreparer
            or type(daily) is not SqlDailyRuntimeRisk
            or type(runtime_sources) is not SqlContinuousRuntimeSources
            or accounts.engine is not engine
            or daily.engine is not engine
            or runtime_sources.engine is not engine
            or accounts.preparer is not preparer
            or accounts.artifacts is not artifacts
            or accounts.codec is not codec
            or daily.codec is not codec
            or runtime_sources.codec is not codec
            or runtime_sources.artifacts is not artifacts
            or runtime_sources.accounts is not accounts
            or runtime_sources.daily is not daily
            or daily.producers is not runtime_sources
            or accounts.coordinator is not daily.coordinator
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_EXACT_CONCRETE_OWNERS_REQUIRED")
        self.engine, self.accounts, self.preparer, self.daily = engine, accounts, preparer, daily
        self.runtime_sources, self.artifacts, self.codec = runtime_sources, artifacts, codec
        self.dispatch_journal = SqlDurableJournal(
            engine, codec=codec, record_types={"daily-dispatch/1": DailyDispatchRecord}
        )
        self._bindings = self._binding_values()
        self._outcomes: object | None = None
        self._original_outcomes: object | None = None
        self._seal = object()
        self._owned: WeakValueDictionary[int, Any] = WeakValueDictionary()
        self._fresh: WeakValueDictionary[str, PreparedContinuousRuntimeAttemptSource] = (
            WeakValueDictionary()
        )
        self._fields: dict[int, tuple[tuple[str, object], ...]] = {}
        self._fingerprints: dict[int, str] = {}
        self._state_fields: dict[
            int, tuple[tuple[object, tuple[tuple[str, object], ...]], ...]
        ] = {}

    def _binding_values(self) -> tuple[object, ...]:
        return (
            self.engine,
            self.accounts,
            self.preparer,
            self.daily,
            self.runtime_sources,
            self.artifacts,
            self.codec,
            self.dispatch_journal,
            self.accounts.engine,
            self.accounts.coordinator,
            self.accounts.preparer,
            self.accounts.artifacts,
            self.accounts.codec,
            self.daily.engine,
            self.daily.coordinator,
            self.daily.producers,
            self.daily.codec,
            self.runtime_sources.engine,
            self.runtime_sources.accounts,
            self.runtime_sources.daily,
            self.runtime_sources.artifacts,
            self.runtime_sources.codec,
            self.dispatch_journal._engine,
            self.dispatch_journal._codec,
        )

    def _require_bindings(self) -> None:
        if any(
            actual is not original
            for actual, original in zip(self._binding_values(), self._bindings, strict=True)
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_BOUND_OWNERS_CHANGED")

    def bind_outcome_sources(self, sources: object) -> None:
        from packages.persistence.continuous_attempt_outcome_sources import (
            SqlContinuousAttemptOutcomeSources,
        )

        self._require_bindings()
        if (
            self._outcomes is not None
            or type(sources) is not SqlContinuousAttemptOutcomeSources
            or sources.attempts is not self
        ):
            raise ContinuousRuntimeAttemptSourceError(
                "ATTEMPT_EXACT_OUTCOME_OWNER_BINDING_REQUIRED"
            )
        sources.require_bindings()
        self._outcomes = self._original_outcomes = sources

    def _outcome_reader(self) -> Any:
        from packages.persistence.continuous_attempt_outcome_sources import (
            SqlContinuousAttemptOutcomeSources,
        )

        if (
            type(self._outcomes) is not SqlContinuousAttemptOutcomeSources
            or self._outcomes is not self._original_outcomes
            or self._outcomes.attempts is not self
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ACTUAL_OUTCOME_OWNER_REQUIRED")
        self._outcomes.require_bindings()
        return self._outcomes

    def _own(self, value: T) -> T:
        self._owned[id(value)] = value
        self._fields[id(value)] = tuple(
            (f.name, getattr(value, f.name)) for f in fields(cast(Any, value))
        )
        states = []

        def retain_fields(record: Any) -> None:
            states.append(
                (record, tuple((f.name, getattr(record, f.name)) for f in fields(record)))
            )

        if type(value) is OriginalContinuousRuntimeAttemptPrefix:
            for snapshot, _ in cast(OriginalContinuousRuntimeAttemptPrefix, value).selected:
                retain_fields(snapshot)
        if type(value) is PreparedContinuousRuntimeAttemptSource:
            for append in cast(PreparedContinuousRuntimeAttemptSource, value).dispatch_appends:
                for record in (append, append.key, append.request, append.receipt, *append.entries):
                    retain_fields(record)
        state: Any = getattr(value, "state", None)
        while type(state) in (_Plan, _Captured, _Resolved):
            retain_fields(state)
            if type(state) is _Resolved:
                for snapshot, _ in state.selected:
                    retain_fields(snapshot)
                for reads in state.dispatches:
                    for read in reads:
                        for record in (read, read.head, read.snapshot, read.snapshot.key):
                            retain_fields(record)
            if type(state) is _Captured:
                for snapshots in state.dispatches:
                    for journal_snapshot in snapshots:
                        retain_fields(journal_snapshot)
                        retain_fields(journal_snapshot.key)
            if type(state) is _Plan:
                for item in state.sources:
                    for record in (
                        item,
                        item.source,
                        item.closure,
                        item.checkpoint,
                        item.action,
                        item.reference,
                        item.request,
                        item.closure.scope,
                        item.source.fence,
                        item.source.fence.fence,
                        item.source.heads,
                        item.closure.previous,
                        item.closure.previous.commit,
                    ):
                        retain_fields(record)
                    if item.descriptor is not None:
                        retain_fields(item.descriptor)
                    if item.closure.outcome_reference is not None:
                        retain_fields(item.closure.outcome_reference)
                        retain_fields(item.closure.outcome_reference.object_ref)
                    for key in item.closure.dispatch_keys:
                        retain_fields(key)
                    if item.closure.unsent_dispatch_head is not None:
                        retain_fields(item.closure.unsent_dispatch_head)
                    if item.closure.unsent_dispatch_receipt is not None:
                        receipt = item.closure.unsent_dispatch_receipt
                        for record in (receipt, receipt.previous_head, receipt.committed_head):
                            retain_fields(record)
                break
            state = state.captured if type(state) is _Resolved else state.plan
        self._state_fields[id(value)] = tuple(states)
        finalize(value, self._fields.pop, id(value), None)
        finalize(value, self._state_fields.pop, id(value), None)
        return value

    def _require(self, value: object, kind: type[Any]) -> None:
        self._require_bindings()
        if (
            type(value) is not kind
            or self._owned.get(id(value)) is not value
            or any(
                getattr(value, name) is not original for name, original in self._fields[id(value)]
            )
            or any(
                getattr(state, name) is not original
                for state, pairs in self._state_fields[id(value)]
                for name, original in pairs
            )
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_OWNED_ORIGINAL_TOKEN_REQUIRED")

    @staticmethod
    def _fingerprint(
        value: PreparedContinuousRuntimeAttemptSource | ResolvedRuntimeAttemptSources,
    ) -> str:
        if type(value) is ResolvedRuntimeAttemptSources:
            state = cast(_Resolved, value.state)
            detached = detached_journal_value(
                (
                    value.sources,
                    tuple(
                        (
                            item.reference,
                            item.closure,
                            item.checkpoint,
                            item.action,
                            item.request,
                            item.dispatches,
                            item.admission_payloads,
                            item.descriptor,
                            item.unsent_key_payload,
                        )
                        for item in state.captured.plan.sources
                    ),
                    tuple(
                        (str(table.table.name), table.account_id, table.rows)
                        for table in state.captured.provenance
                    ),
                    state.dispatches,
                )
            )
            return sha256(canonical_json_bytes(detached)).hexdigest()
        value = cast(PreparedContinuousRuntimeAttemptSource, value)
        return content_digest(
            (
                value.reference,
                value.source,
                value.closure,
                value.action,
                value.envelopes,
                None if value.descriptor is None else value.descriptor.plan.descriptor,
                tuple((item.key, item.request, item.receipt) for item in value.dispatch_appends),
            )
        )

    def require_prepared(self, value: PreparedContinuousRuntimeAttemptSource) -> None:
        self._require(value, PreparedContinuousRuntimeAttemptSource)
        self.accounts.require_resolved(value.previous)
        self.daily.require_resolved_snapshot(value.current)
        for admission in value.admissions:
            self.daily.require_admission_view(admission)
        if value.descriptor is not None:
            self.runtime_sources.require_resolved(value.descriptor)
        if value.outcome is not None:
            self._outcome_reader().require_observation(value.outcome)
        if self._fingerprints.get(id(value)) != self._fingerprint(value):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_SOURCE_CONTENT_CHANGED")

    def _fresh_prefix(
        self, previous: ResolvedContinuousAccount, current: ResolvedDailyRuntimeSnapshot
    ) -> ReconciliationHeads:
        self._require_bindings()
        self.accounts.require_resolved(previous)
        self.daily.require_resolved_snapshot(current)
        checkpoint = previous.checkpoint
        if (
            current.raw.account_id != checkpoint.state.account_id
            or tuple(sorted(checkpoint.state.commitments, key=lambda item: item.commitment_id))
            != tuple(binding.commitment for binding in current.obligations.bindings)
            or not checkpoint.now
            <= current.raw.receipt.validated_at
            < current.raw.receipt.valid_until
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ACTUAL_CURRENT_PREFIX_DIFFERS")
        return ReconciliationHeads(
            checkpoint.current.snapshot.journal_sha256,
            checkpoint.current.snapshot.order_sha256,
            current.obligations.semantic_sha256,
            daily_runtime_effect_watermark(
                attempt_envelopes=current.attempt_envelopes, observed_groups=current.observed_groups
            ),
            daily_attempt_inventory_sha256(current.attempts),
            0 if current.control is None else current.control.sequence_number,
            current.raw.receipt.fence.fencing_generation,
        )

    def _admission_refs(
        self,
        graph: _Graph,
        current: ResolvedDailyRuntimeSnapshot,
        admissions: tuple[RetainedDailyAdmission, ...],
    ) -> tuple[ContinuousEvidenceRef, ...]:
        if type(admissions) is not tuple or not 1 <= len(admissions) <= 4:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_ADMISSIONS_REQUIRED")
        result = []
        for view in admissions:
            self.daily.require_admission_view(view)
            matching = [
                record for record in current.admissions if record.command_id == view.command_id
            ]
            if (
                len(matching) != 1
                or matching[0].semantic_sha256 != view.record_sha256
                or self.codec.encode_record(matching[0]) != view.canonical_payload
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ORIGINAL_RETAINED_ADMISSION_DIFFERS"
                )
            ref = ContinuousEvidenceRef(
                "daily-admission-producer/1",
                ObjectRef(view.payload_sha256, len(view.canonical_payload)),
                view.record_sha256,
            )
            graph.admit((ref.object_ref,))
            graph.payloads[ref.object_ref.object_sha256] = view.canonical_payload
            result.append(ref)
        if len(set(result)) != len(result):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_ADMISSION_DUPLICATE")
        return tuple(sorted(result, key=lambda ref: ref.semantic_sha256))

    def retain_pending(
        self,
        *,
        coordinator_command_id: str,
        previous: ResolvedContinuousAccount,
        current: ResolvedDailyRuntimeSnapshot,
        admissions: tuple[RetainedDailyAdmission, ...],
    ) -> PreparedContinuousRuntimeAttemptSource:
        heads = self._fresh_prefix(previous, current)
        graph = _Graph(self.artifacts, self.codec)
        references = self._admission_refs(graph, current, admissions)
        checkpoint = previous.checkpoint
        submitted = {item.order_id: item for item in checkpoint.state.submissions}
        bindings = {item.commitment.commitment_id: item for item in current.obligations.bindings}
        existing = {item.attempt_id for item in current.attempts}
        prepared = []
        for view in admissions:
            for original in view.bindings:
                hold = original.commitment
                submission = submitted.get(hold.order_id)
                if (
                    bindings.get(hold.commitment_id) != original
                    or submission is None
                    or submission.submission_attempt_id in existing
                ):
                    raise ContinuousRuntimeAttemptSourceError(
                        "ATTEMPT_ORIGINAL_UNSENT_HOLD_REQUIRED"
                    )
                venue_request = DailyVenueSubmissionRequest(
                    submission=submission,
                    original_commitment=hold,
                    source_account_id=current.raw.account_id,
                    source_account_binding_sha256=previous.receipt.commit.scope.account_binding_sha256,
                    venue_account_id=self.runtime_sources.venue_model.account_id,
                    venue_model=self.runtime_sources.venue_reference,
                    original_admission_sha256=view.admission.semantic_sha256,
                )
                prepared.append(
                    prepare_daily_attempt(
                        request=venue_request,
                        original_admission=view.admission,
                        admission_source=VenueSourceReference(
                            original.projection,
                            view.record_sha256,
                            ObjectRef(view.payload_sha256, len(view.canonical_payload)),
                        ),
                        original_hold=original,
                        prepared_at=current.raw.receipt.validated_at,
                    )
                )
        preparations = tuple(sorted(prepared, key=lambda item: item.attempt_id))
        events = tuple(
            DailyAttemptEvent(
                attempt_id=item.attempt_id,
                sequence=1,
                previous_event_sha256=None,
                state=SubmissionAttemptState.PENDING,
                recorded_at=current.raw.receipt.validated_at,
            )
            for item in preparations
        )
        return self._retain_metadata(
            graph=graph,
            kind="pending",
            coordinator_command_id=coordinator_command_id,
            previous=previous,
            current=current,
            admissions=admissions,
            admission_refs=references,
            preparations=preparations,
            events=events,
            heads=heads,
        )

    def _retain_metadata(
        self,
        *,
        graph: _Graph,
        kind: Any,
        coordinator_command_id: str,
        previous: ResolvedContinuousAccount,
        current: ResolvedDailyRuntimeSnapshot,
        admissions: tuple[RetainedDailyAdmission, ...],
        admission_refs: tuple[ContinuousEvidenceRef, ...],
        preparations: tuple[DailyAttemptPreparation, ...],
        events: tuple[DailyAttemptEvent, ...],
        heads: ReconciliationHeads,
        dispatch_keys: tuple[JournalKey, ...] = (),
        prior_dispatches: tuple[DailyDispatchClaim, ...] = (),
        descriptor: ResolvedRuntimeDescriptor | None = None,
        accounting_command: AccountingCommand | None = None,
        dispatch_appends: tuple[PreparedJournalAppend, ...] = (),
        valid_until: datetime | None = None,
        unsent_dispatch_head: JournalHead | None = None,
        unsent_dispatch_receipt: JournalReceipt | None = None,
        outcome: object | None = None,
        outcome_reference: ContinuousEvidenceRef | None = None,
    ) -> PreparedContinuousRuntimeAttemptSource:
        checkpoint = previous.checkpoint
        checked_at = current.raw.receipt.validated_at
        cp_ref = graph.encode(CHECKPOINT_SCHEMA, checkpoint)
        for claim in (
            *prior_dispatches,
            *(event.dispatch for event in events if event.dispatch is not None),
        ):
            if graph.encode("daily-dispatch/1", claim.record).object_ref != claim.record_ref:
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ORIGINAL_DISPATCH_OBJECT_DIFFERS"
                )
        if descriptor is not None:
            self.runtime_sources.require_resolved(descriptor)
            if (
                graph.encode(descriptor.plan.reference.schema_id, descriptor.plan.descriptor)
                != descriptor.plan.reference
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ORIGINAL_DESCRIPTOR_BYTES_DIFFER"
                )
        closure = ContinuousRuntimeAttemptClosure(
            kind=kind,
            scope=previous.receipt.commit.scope,
            previous=previous.receipt,
            previous_checkpoint=cp_ref,
            events=events,
            preparations=preparations,
            admission_records=admission_refs,
            dispatch_keys=dispatch_keys,
            prior_dispatches=prior_dispatches,
            descriptor=None if descriptor is None else descriptor.plan.reference,
            descriptor_receipt=None if descriptor is None else descriptor.descriptor.receipt,
            unsent_dispatch_head=unsent_dispatch_head,
            unsent_dispatch_receipt=unsent_dispatch_receipt,
            outcome_reference=outcome_reference,
        )
        closure_ref = graph.encode(RUNTIME_ATTEMPT_CLOSURE_SCHEMA, closure)
        source = RuntimeAttemptAccountingSource(
            account_id=current.raw.account_id,
            coordinator_command_id=coordinator_command_id,
            coordinator_sequence=previous.receipt.commit.sequence + 1,
            state=checkpoint.state,
            context=continuous_runtime_action_context(
                checkpoint,
                command_id=coordinator_command_id
                if accounting_command is None
                else accounting_command.command_id,
                activation=accounting_command is not None
                and isinstance(accounting_command.payload, ActivateRuntimeCommitments),
                checked_at=checked_at,
            ),
            execution_policy=checkpoint.inputs.spec.execution_policy,
            obligations=current.obligations,
            heads=heads,
            fence=daily_fence_reference(current.raw.receipt),
            checked_at=checked_at,
            valid_until=valid_until
            if valid_until is not None
            else min(
                current.raw.receipt.valid_until,
                *(item.original_admission.expires_at for item in preparations),
            )
            if kind == "pending"
            else current.raw.receipt.valid_until,
            accounting_command=accounting_command,
            source_references=(closure_ref,),
        )
        reference = graph.encode(RUNTIME_ATTEMPT_SOURCE_SCHEMA, source)
        action = ContinuousRuntimeAction(
            action_id=coordinator_command_id,
            stream_id=checkpoint.inputs.spec.run_id,
            previous_checkpoint_sha256=checkpoint.semantic_sha256,
            source_closure_sha256=source.semantic_sha256,
            checked_at=source.checked_at,
            command=accounting_command,
            attempt_events=events if accounting_command is None else (),
        )
        envelopes = tuple(
            DailyAttemptEnvelope(
                account_id=source.account_id,
                coordinator_command_id=coordinator_command_id,
                coordinator_sequence=source.coordinator_sequence,
                event=event,
                source_ref=reference,
            )
            for event in events
        )
        graph.publish()
        result = self._own(
            PreparedContinuousRuntimeAttemptSource(
                reference,
                source,
                closure,
                action,
                envelopes,
                previous,
                current,
                admissions,
                self._seal,
                descriptor,
                dispatch_appends,
                outcome,
            )
        )
        self._fingerprints[id(result)] = self._fingerprint(result)
        finalize(result, self._fingerprints.pop, id(result), None)
        self._fresh[reference.semantic_sha256] = result
        return result

    def retain_activation(
        self,
        *,
        coordinator_command_id: str,
        previous: ResolvedContinuousAccount,
        current: ResolvedDailyRuntimeSnapshot,
        admissions: tuple[RetainedDailyAdmission, ...],
        descriptor: ResolvedRuntimeDescriptor,
        attempt_ids: tuple[str, ...],
    ) -> PreparedContinuousRuntimeAttemptSource:
        """Prepare an actual common activation and prospective journal writes; no delivery."""
        heads = self._fresh_prefix(previous, current)
        self.runtime_sources.require_resolved(descriptor)
        if (
            type(descriptor) is not ResolvedRuntimeDescriptor
            or descriptor.plan.previous is not previous
            or descriptor.plan.daily is not current
            or descriptor.plan.descriptor.request_kind != "activation_dependencies"
            or descriptor.plan.descriptor.original_checked_at != current.raw.receipt.validated_at
            or descriptor.descriptor.receipt is None
        ):
            raise ContinuousRuntimeAttemptSourceError(
                "ACTIVATION_ACTUAL_ORIGINAL_DESCRIPTOR_REQUIRED"
            )
        if (
            type(attempt_ids) is not tuple
            or not 1 <= len(attempt_ids) <= 4
            or attempt_ids != tuple(sorted(set(attempt_ids)))
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_EXACT_SORTED_IDS_REQUIRED")
        by_id = {item.attempt_id: item for item in current.attempts}
        chosen = tuple(by_id.get(identity) for identity in attempt_ids)
        if any(item is None or item.state is not SubmissionAttemptState.PENDING for item in chosen):
            raise ContinuousRuntimeAttemptSourceError("ACTIVATION_ACTUAL_PENDING_PREFIX_REQUIRED")
        attempts = cast(tuple[CanonicalDailyAttempt, ...], chosen)
        original_batch = attempts[0].preparation.original_admission.decision.batch
        if any(
            item.preparation.original_admission.decision.batch.target != original_batch.target
            for item in attempts
        ):
            raise ContinuousRuntimeAttemptSourceError("ACTIVATION_COMMON_ORIGINAL_BATCH_REQUIRED")
        cp, at = previous.checkpoint, current.raw.receipt.validated_at
        snapshot = cp.current.snapshot
        batch = replace(
            original_batch,
            snapshot_sha256=snapshot.semantic_sha256,
            intents=tuple(item.preparation.request.submission.intent for item in attempts),
        )
        port = self.runtime_sources.evidence_port(descriptor)
        loss, drawdown = continuous_runtime_loss_inputs(cp)
        evidence = port.build(
            snapshot=snapshot,
            batch=batch,
            phase="activation",
            evaluated_at=at,
            accepted_intent_ids=dict(cp.accepted).get(batch.target.trigger.execution_session, ()),
            daily_return=loss,
            drawdown=drawdown,
            request_rows=cp.request_rows,
        )
        decision = evaluate_daily_risk(port.assignment.policy, snapshot, batch, evidence, at)
        if not decision.approved:
            raise ContinuousRuntimeAttemptSourceError("ACTIVATION_ACTUAL_RISK_DID_NOT_APPROVE")
        holds = {
            binding.commitment.commitment_id: binding for binding in current.obligations.bindings
        }
        dispatches = tuple(
            prepare_daily_dispatch(
                attempt=attempt,
                activation=prepare_daily_activation(
                    preparation=attempt.preparation,
                    current_hold=holds[attempt.preparation.original_hold.commitment.commitment_id],
                    snapshot=snapshot,
                    evidence=evidence,
                    decision=decision,
                    heads=heads,
                    fence=daily_fence_reference(current.raw.receipt),
                    checked_at=at,
                ),
                command_id=canonical_id(
                    "daily-dispatch", coordinator_command_id, attempt.attempt_id
                ),
                dispatched_at=at,
            )
            for attempt in attempts
        )
        # Payload identity determines the accounting command ID; the first
        # shared preparation uses the same canonical reduction point. Its
        # causal ID is replaced by the derived command ID, then recomputed.
        context = continuous_runtime_action_context(
            cp, command_id=coordinator_command_id, activation=True, checked_at=at
        )
        activation = prepare_daily_runtime_activation(
            state=cp.state,
            context=context,
            execution_policy=cp.inputs.spec.execution_policy,
            attempts=attempts,
            dispatches=dispatches,
            accounting=self.runtime_sources.accounting,
        )
        context = continuous_runtime_action_context(
            cp, command_id=activation.command.command_id, activation=True, checked_at=at
        )
        activation = prepare_daily_runtime_activation(
            state=cp.state,
            context=context,
            execution_policy=cp.inputs.spec.execution_policy,
            attempts=attempts,
            dispatches=dispatches,
            accounting=self.runtime_sources.accounting,
        )
        key = self._dispatch_key(previous.receipt.commit.scope, attempts[0].preparation.request)
        head = self.dispatch_journal.read_head(key)
        appends, events = [], []
        for attempt, record in zip(attempts, dispatches, strict=True):
            payload = self.codec.encode_record(record)
            append = self.dispatch_journal.prepare_append(
                key,
                JournalAppend(
                    record.command_id,
                    record.semantic_sha256,
                    head,
                    (JournalRecord(record.record_id, "daily-dispatch/1", payload),),
                ),
            )
            head = append.receipt.committed_head
            claim = DailyDispatchClaim(
                record=record,
                receipt=append.receipt,
                record_ref=ObjectRef(sha256(payload).hexdigest(), len(payload)),
            )
            appends.append(append)
            events.append(
                DailyAttemptEvent(
                    attempt_id=attempt.attempt_id,
                    sequence=len(attempt.events) + 1,
                    previous_event_sha256=attempt.events[-1].semantic_sha256,
                    state=SubmissionAttemptState.IN_FLIGHT,
                    recorded_at=at,
                    dispatch=claim,
                )
            )
        graph = _Graph(self.artifacts, self.codec)
        refs = self._admission_refs(graph, current, admissions)
        return self._retain_metadata(
            graph=graph,
            kind="activation",
            coordinator_command_id=coordinator_command_id,
            previous=previous,
            current=current,
            admissions=admissions,
            admission_refs=refs,
            preparations=tuple(item.preparation for item in attempts),
            events=tuple(events),
            heads=heads,
            dispatch_keys=(key,),
            descriptor=descriptor,
            accounting_command=activation.command,
            dispatch_appends=tuple(appends),
            valid_until=min(record.activation.expires_at for record in dispatches),
        )

    @staticmethod
    def _dispatch_key(
        scope: ContinuousAccountScope, request: DailyVenueSubmissionRequest
    ) -> JournalKey:
        return JournalKey(
            "coordinator",
            canonical_id("daily-dispatch-stream", scope.semantic_sha256),
            request.source_account_id,
            "daily-dispatch/1",
            "synthetic",
            content_digest(
                (
                    "daily-dispatch-scope/1",
                    request.source_account_id,
                    request.source_account_binding_sha256,
                    request.venue_account_id,
                    request.venue_model,
                )
            ),
        )

    @staticmethod
    def _dispatch_prefix(
        key: JournalKey, attempts: tuple[CanonicalDailyAttempt, ...]
    ) -> tuple[JournalHead, JournalReceipt | None]:
        """Compare complete canonical claim history to one original journal prefix.

        Original source resolution authenticates each claimed journal record; this
        check cannot turn the staged history into separate financial authority.
        """
        receipts = sorted(
            (
                event.dispatch.receipt
                for attempt in attempts
                for event in attempt.events
                if event.dispatch is not None
                and event.dispatch.receipt.committed_head.key_sha256 == key.semantic_sha256
            ),
            key=lambda receipt: receipt.committed_head.sequence,
        )
        head = empty_head(key)
        terminal: JournalReceipt | None = None
        for receipt in receipts:
            if receipt.previous_head != head or len(receipt.record_ids) != 1:
                raise ContinuousRuntimeAttemptSourceError(
                    "UNSENT_COMPLETE_ORIGINAL_DISPATCH_PREFIX_DIFFERS"
                )
            head, terminal = receipt.committed_head, receipt
        return head, terminal

    def retain_expired_unsent(
        self,
        *,
        coordinator_command_id: str,
        previous: ResolvedContinuousAccount,
        current: ResolvedDailyRuntimeSnapshot,
        admissions: tuple[RetainedDailyAdmission, ...],
        attempt_id: str,
    ) -> PreparedContinuousRuntimeAttemptSource:
        """Release one originally pending, never-dispatched hold after its expiry."""
        heads = self._fresh_prefix(previous, current)
        cp, at = previous.checkpoint, current.raw.receipt.validated_at
        if any(
            event.event_id in cp.pending_ids and event.knowledge_at <= at for event in cp.events
        ):
            raise ContinuousRuntimeAttemptSourceError("UNSENT_ACTUAL_SOURCE_FRONTIER_REQUIRED")
        actual = next((item for item in current.attempts if item.attempt_id == attempt_id), None)
        if actual is None or actual.state is not SubmissionAttemptState.PENDING:
            raise ContinuousRuntimeAttemptSourceError("UNSENT_ORIGINAL_PENDING_HISTORY_REQUIRED")
        if at < actual.preparation.original_hold.commitment.expires_at:
            raise ContinuousRuntimeAttemptSourceError("UNSENT_ORIGINAL_EXPIRY_NOT_REACHED")
        key = self._dispatch_key(previous.receipt.commit.scope, actual.preparation.request)
        head, terminal = self._dispatch_prefix(key, current.attempts)
        if self.dispatch_journal.read_head(key) != head:
            raise ContinuousRuntimeAttemptSourceError("UNSENT_UNCLAIMED_DISPATCH_JOURNAL_RECORD")
        proof = DailyUnsentProof(
            account_id=current.raw.account_id,
            attempt_id=attempt_id,
            request_sha256=actual.preparation.request.semantic_sha256,
            attempt_history_sha256=actual.semantic_sha256,
            commitment_sha256=actual.preparation.original_hold.commitment.semantic_sha256,
            heads=heads,
            fence=daily_fence_reference(current.raw.receipt),
            checked_at=at,
            reason="expired",
            owner_command=None,
        )
        payload = self._unsent_payload(cp, actual, proof)
        command = AccountingCommand(
            canonical_id(
                "continuous-unsent-release", coordinator_command_id, payload.semantic_sha256
            ),
            payload,
        )
        self._validate_unsent_accounting(cp, actual, proof, command)
        event = DailyAttemptEvent(
            attempt_id=attempt_id,
            sequence=len(actual.events) + 1,
            previous_event_sha256=actual.events[-1].semantic_sha256,
            state=SubmissionAttemptState.ABANDONED,
            recorded_at=at,
            unsent_proof=proof,
        )
        reduce_daily_attempt(actual.preparation, (*actual.events, event))
        graph = _Graph(self.artifacts, self.codec)
        refs = self._admission_refs(graph, current, admissions)
        return self._retain_metadata(
            graph=graph,
            kind="expired_unsent",
            coordinator_command_id=coordinator_command_id,
            previous=previous,
            current=current,
            admissions=admissions,
            admission_refs=refs,
            preparations=(actual.preparation,),
            events=(event,),
            heads=heads,
            dispatch_keys=(key,),
            accounting_command=command,
            unsent_dispatch_head=head,
            unsent_dispatch_receipt=terminal,
        )

    @staticmethod
    def _unsent_payload(
        cp: CausalEngineCheckpoint, attempt: CanonicalDailyAttempt, proof: DailyUnsentProof
    ) -> ReleaseRuntimeUnsent:
        hold = attempt.preparation.original_hold.commitment
        return ReleaseRuntimeUnsent(
            account_id=cp.state.account_id,
            commitment_id=hold.commitment_id,
            expected_commitment_sha256=hold.semantic_sha256,
            source_state_sha256=cp.state.semantic_sha256,
            attempt_history_sha256=attempt.semantic_sha256,
            locked_unsent_proof_sha256=proof.semantic_sha256,
            proof_at=proof.checked_at,
            reason="expired",
            owner_command_sha256=None,
        )

    def _validate_unsent_accounting(
        self,
        cp: CausalEngineCheckpoint,
        attempt: CanonicalDailyAttempt,
        proof: DailyUnsentProof,
        command: AccountingCommand,
    ) -> None:
        if (
            attempt.state is not SubmissionAttemptState.PENDING
            or proof.reason != "expired"
            or proof.owner_command is not None
            or command.payload != self._unsent_payload(cp, attempt, proof)
        ):
            raise ContinuousRuntimeAttemptSourceError("UNSENT_EXACT_EXPIRED_RELEASE_REQUIRED")
        transition = self.runtime_sources.accounting.advance(
            state=cp.state,
            command=command,
            context=continuous_runtime_action_context(
                cp, command_id=command.command_id, activation=False, checked_at=proof.checked_at
            ),
            policy=cp.inputs.spec.execution_policy,
        )
        if (
            transition.disposition != "applied"
            or transition.reasons
            or transition.due_events
            or transition.journal_entries
        ):
            raise ContinuousRuntimeAttemptSourceError("UNSENT_CANONICAL_RELEASE_NOT_APPLIED")

    def inspect_dispatch_keys(
        self,
        *,
        previous: ResolvedContinuousAccount,
        current: ResolvedDailyRuntimeSnapshot,
        attempt_ids: tuple[str, ...],
    ) -> tuple[JournalKey, ...]:
        """Inspect original journal locations; this returns no financial or delivery permit."""
        self._fresh_prefix(previous, current)
        if type(attempt_ids) is not tuple or not 1 <= len(attempt_ids) <= 4:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_EXACT_SORTED_IDS_REQUIRED")
        for identifier in attempt_ids:
            journal_identifier(identifier)
        if attempt_ids != tuple(sorted(set(attempt_ids))):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_EXACT_SORTED_IDS_REQUIRED")
        by_id = {item.attempt_id: item for item in current.attempts}
        keys = {}
        for identifier in attempt_ids:
            attempt = by_id.get(identifier)
            if attempt is None:
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_KNOWN_ID_REQUIRED")
            key = self._dispatch_key(previous.receipt.commit.scope, attempt.preparation.request)
            claims = tuple(event.dispatch for event in attempt.events if event.dispatch is not None)
            if (
                len(claims) > 1
                or (
                    bool(claims)
                    != (
                        attempt.state
                        not in (SubmissionAttemptState.PENDING, SubmissionAttemptState.ABANDONED)
                    )
                )
                or any(
                    claim.record.preparation != attempt.preparation
                    or claim.receipt.committed_head.key_sha256 != key.semantic_sha256
                    or claim.receipt.previous_head.key_sha256 != key.semantic_sha256
                    for claim in claims
                )
            ):
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_DISPATCH_KEY_DIFFERS")
            keys[key.semantic_sha256] = key
        return tuple(keys[digest] for digest in sorted(keys))

    def retain_unknown(
        self,
        *,
        coordinator_command_id: str,
        previous: ResolvedContinuousAccount,
        current: ResolvedDailyRuntimeSnapshot,
        admissions: tuple[RetainedDailyAdmission, ...],
        attempt_ids: tuple[str, ...],
        reason: str,
        dispatch_keys: tuple[JournalKey, ...],
    ) -> PreparedContinuousRuntimeAttemptSource:
        """Retain uncertainty after an actual original send; never infer acknowledgement."""
        heads = self._fresh_prefix(previous, current)
        if (
            type(attempt_ids) is not tuple
            or not 1 <= len(attempt_ids) <= 4
            or (attempt_ids != tuple(sorted(set(attempt_ids))))
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_EXACT_SORTED_IDS_REQUIRED")
        by_id = {item.attempt_id: item for item in current.attempts}
        attempts = tuple(by_id.get(identifier) for identifier in attempt_ids)
        if any(
            item is None or item.state is not SubmissionAttemptState.IN_FLIGHT for item in attempts
        ):
            raise ContinuousRuntimeAttemptSourceError("UNKNOWN_REQUIRES_ACTUAL_IN_FLIGHT_HISTORY")
        actual = cast(tuple[CanonicalDailyAttempt, ...], attempts)
        claims = tuple(item.events[-1].dispatch for item in actual)
        if any(claim is None for claim in claims):
            raise ContinuousRuntimeAttemptSourceError("UNKNOWN_ORIGINAL_DISPATCH_MISSING")
        events = tuple(
            DailyAttemptEvent(
                attempt_id=item.attempt_id,
                sequence=len(item.events) + 1,
                previous_event_sha256=item.events[-1].semantic_sha256,
                state=SubmissionAttemptState.UNKNOWN,
                recorded_at=current.raw.receipt.validated_at,
                reason=reason,
            )
            for item in actual
        )
        graph = _Graph(self.artifacts, self.codec)
        refs = self._admission_refs(graph, current, admissions)
        return self._retain_metadata(
            graph=graph,
            kind="unknown",
            coordinator_command_id=coordinator_command_id,
            previous=previous,
            current=current,
            admissions=admissions,
            admission_refs=refs,
            preparations=tuple(item.preparation for item in actual),
            events=events,
            heads=heads,
            dispatch_keys=dispatch_keys,
            prior_dispatches=cast(tuple[DailyDispatchClaim, ...], claims),
        )

    def retain_outcome(
        self,
        *,
        coordinator_command_id: str,
        previous: ResolvedContinuousAccount,
        current: ResolvedDailyRuntimeSnapshot,
        admissions: tuple[RetainedDailyAdmission, ...],
        attempt_id: str,
        observation: object,
    ) -> PreparedContinuousRuntimeAttemptSource:
        """Retain a known original captured order outcome without economic effects."""
        heads = self._fresh_prefix(previous, current)
        reader = self._outcome_reader()
        reader.require_observation(observation)
        observed = cast(Any, observation)
        matches = [item for item in current.attempts if item.attempt_id == attempt_id]
        if (
            len(matches) != 1
            or matches[0].state
            not in (
                SubmissionAttemptState.IN_FLIGHT,
                SubmissionAttemptState.UNKNOWN,
            )
            or observed.plan.outcome is None
            or observed.plan.evidence.attempt_id != attempt_id
        ):
            raise ContinuousRuntimeAttemptSourceError("OUTCOME_ACTUAL_DEFINITIVE_ORDER_REQUIRED")
        attempt = matches[0]
        claim, parent = reader._original_dispatch(attempt, current.attempt_envelopes)
        evidence = observed.plan.evidence
        if (
            evidence.activation_source != parent.source_ref
            or evidence.activation.commit.sequence != parent.coordinator_sequence
            or evidence.activation.commit.scope != previous.receipt.commit.scope
            or evidence.registration != reader._packet(observed.plan.checkpoint, claim)
            or not claim.record.dispatched_at
            <= observed.plan.outcome.observed_at
            <= current.raw.receipt.validated_at
        ):
            raise ContinuousRuntimeAttemptSourceError("OUTCOME_ORIGINAL_CAPTURE_LINEAGE_DIFFERS")
        event = DailyAttemptEvent(
            attempt_id=attempt_id,
            sequence=len(attempt.events) + 1,
            previous_event_sha256=attempt.events[-1].semantic_sha256,
            state=SubmissionAttemptState.CONFIRMED
            if attempt.state is SubmissionAttemptState.IN_FLIGHT
            else SubmissionAttemptState.RESOLVED,
            recorded_at=current.raw.receipt.validated_at,
            outcome=observed.plan.outcome,
        )
        reduce_daily_attempt(attempt.preparation, (*attempt.events, event))
        graph = _Graph(self.artifacts, self.codec)
        graph.admit(observed.plan.object_refs)
        refs = self._admission_refs(graph, current, admissions)
        return self._retain_metadata(
            graph=graph,
            kind="outcome",
            coordinator_command_id=coordinator_command_id,
            previous=previous,
            current=current,
            admissions=admissions,
            admission_refs=refs,
            preparations=(attempt.preparation,),
            events=(event,),
            heads=heads,
            dispatch_keys=(
                self._dispatch_key(previous.receipt.commit.scope, attempt.preparation.request),
            ),
            prior_dispatches=(claim,),
            outcome=observation,
            outcome_reference=observed.plan.reference,
        )

    @staticmethod
    def _action(
        source: RuntimeAttemptAccountingSource,
        closure: ContinuousRuntimeAttemptClosure,
        checkpoint: CausalEngineCheckpoint,
    ) -> ContinuousRuntimeAction:
        return ContinuousRuntimeAction(
            action_id=source.coordinator_command_id,
            stream_id=checkpoint.inputs.spec.run_id,
            previous_checkpoint_sha256=checkpoint.semantic_sha256,
            source_closure_sha256=source.semantic_sha256,
            checked_at=source.checked_at,
            command=source.accounting_command,
            attempt_events=closure.events if source.accounting_command is None else (),
        )

    def _validate_source(self, item: _Source) -> None:
        source, closure, cp = item.source, item.closure, item.checkpoint
        if type(cp.inputs) is not ContinuousEngineInputs:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_CONTINUOUS_CHECKPOINT_REQUIRED")
        activation = closure.kind == "activation"
        expected_payload = {
            "pending": type(None),
            "unknown": type(None),
            "outcome": type(None),
            "activation": ActivateRuntimeCommitments,
            "expired_unsent": ReleaseRuntimeUnsent,
        }.get(closure.kind)
        if (
            expected_payload is None
            or type(
                None if source.accounting_command is None else source.accounting_command.payload
            )
            is not expected_payload
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_OPERATION_SOURCE_NOT_YET_SUPPORTED")
        if (
            source.account_id != closure.scope.account_id
            or source.coordinator_sequence != closure.previous.commit.sequence + 1
            or cp.semantic_sha256 != closure.previous_checkpoint.semantic_sha256
            or cp.inputs.spec.account_id != closure.scope.account_id
            or cp.inputs.spec.deployment_id != closure.scope.stream_id
            or cp.inputs.spec.account_binding_sha256 != closure.scope.account_binding_sha256
            or source.state != cp.state
            or source.execution_policy != cp.inputs.spec.execution_policy
            or source.checked_at < cp.now
            or any(event.recorded_at != source.checked_at for event in closure.events)
            or source.context
            != continuous_runtime_action_context(
                cp,
                command_id=source.coordinator_command_id
                if source.accounting_command is None
                else source.accounting_command.command_id,
                activation=activation,
                checked_at=source.checked_at,
            )
            or source.heads.control_revision > MAX_ROWS
            or source.heads.ledger_sha256 != cp.current.snapshot.journal_sha256
            or source.heads.order_sha256 != cp.current.snapshot.order_sha256
            or tuple(binding.commitment for binding in source.obligations.bindings)
            != tuple(sorted(cp.state.commitments, key=lambda hold: hold.commitment_id))
            or item.action != self._action(source, closure, cp)
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_CHECKPOINT_SOURCE_DIFFERS")
        if closure.kind == "pending" and any(
            event.sequence != 1
            or event.previous_event_sha256 is not None
            or not prep.original_admission.recorded_at
            <= source.checked_at
            < prep.original_admission.expires_at
            or source.valid_until > prep.original_admission.expires_at
            for prep, event in zip(closure.preparations, closure.events, strict=True)
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_PENDING_WINDOW_DIFFERS")
        if (closure.kind == "outcome") != (item.outcome_plan is not None):
            raise ContinuousRuntimeAttemptSourceError("OUTCOME_ORIGINAL_CAPTURE_PLAN_REQUIRED")
        if activation and (
            item.descriptor is None
            or item.descriptor_plan is None
            or closure.descriptor_receipt is None
            or item.descriptor.previous != closure.previous
            or item.descriptor.scope != closure.scope
            or item.descriptor.request_kind != "activation_dependencies"
            or item.descriptor.original_checked_at != source.checked_at
            or item.descriptor.captured_fence != source.fence
            or item.descriptor.obligations_sha256 != source.obligations.semantic_sha256
            or item.descriptor.attempts_sha256 != source.heads.attempt_sha256
            or any(
                event.dispatch is None
                or event.dispatch.record.activation.snapshot != cp.current.snapshot
                or event.dispatch.record.activation.checked_at != source.checked_at
                or source.valid_until > event.dispatch.record.activation.expires_at
                for event in closure.events
            )
        ):
            raise ContinuousRuntimeAttemptSourceError(
                "ACTIVATION_ORIGINAL_DESCRIPTOR_SNAPSHOT_DIFFERS"
            )

    def prepare_attempt_source_read(
        self, references: tuple[ContinuousEvidenceRef, ...]
    ) -> RuntimeAttemptSourcePlan:
        self._require_bindings()
        try:
            if (
                type(references) is not tuple
                or not 1 <= len(references) <= 4096
                or (len(set(references)) != len(references))
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_EXACT_REFERENCE_INVENTORY_REQUIRED"
                )
            graph = _Graph(self.artifacts, self.codec)
            graph.admit(tuple(ref.object_ref for ref in references))
            sources = tuple(
                graph.read(ref, RuntimeAttemptAccountingSource, RUNTIME_ATTEMPT_SOURCE_SCHEMA)
                for ref in references
            )
            if any(len(source.source_references) != 1 for source in sources):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_SINGLE_ORIGINAL_CLOSURE_REQUIRED"
                )
            graph.admit(tuple(source.source_references[0].object_ref for source in sources))
            closures = tuple(
                graph.read(
                    source.source_references[0],
                    ContinuousRuntimeAttemptClosure,
                    RUNTIME_ATTEMPT_CLOSURE_SCHEMA,
                )
                for source in sources
            )
            graph.admit(
                tuple(
                    ref.object_ref
                    for closure in closures
                    for ref in (
                        closure.previous_checkpoint,
                        *closure.admission_records,
                        *((closure.descriptor,) if closure.descriptor is not None else ()),
                        *(
                            (closure.outcome_reference,)
                            if closure.outcome_reference is not None
                            else ()
                        ),
                    )
                )
            )
            descriptor_values = tuple(
                None
                if closure.descriptor is None
                else graph.read(
                    closure.descriptor, ContinuousRuntimeSourceDescriptor, RUNTIME_SOURCE_SCHEMA
                )
                for closure in closures
            )
            graph.admit(
                tuple(
                    ref.object_ref
                    for descriptor in descriptor_values
                    if descriptor is not None
                    for ref in (
                        descriptor.request,
                        descriptor.market_source,
                        *(ref for role in descriptor.role_references for ref in role.references),
                    )
                )
            )
            graph.admit(
                tuple(claim.record_ref for closure in closures for claim in self._claims(closure))
            )
            items = []
            for ref, source, closure, descriptor in zip(
                references, sources, closures, descriptor_values, strict=True
            ):
                cp = graph.read(
                    closure.previous_checkpoint, CausalEngineCheckpoint, CHECKPOINT_SCHEMA
                )
                action = self._action(source, closure, cp)
                request = graph.encode(CONTINUOUS_RUNTIME_ACTION_SCHEMA, action)
                claims = self._claims(closure)
                keys = {key.semantic_sha256: key for key in closure.dispatch_keys}
                dispatches = []
                for claim in claims:
                    key = keys.get(claim.receipt.committed_head.key_sha256)
                    if key is None or graph.raw(claim.record_ref) != self.codec.encode_record(
                        claim.record
                    ):
                        raise ContinuousRuntimeAttemptSourceError(
                            "ATTEMPT_ORIGINAL_DISPATCH_OBJECT_DIFFERS"
                        )
                    request_source = claim.record.preparation.request
                    scope = content_digest(
                        (
                            "daily-dispatch-scope/1",
                            request_source.source_account_id,
                            request_source.source_account_binding_sha256,
                            request_source.venue_account_id,
                            request_source.venue_model,
                        )
                    )
                    if (
                        key.namespace,
                        key.account_scope,
                        key.source_provider,
                        key.source_environment,
                        key.source_scope_sha256,
                    ) != ("coordinator", source.account_id, "daily-dispatch/1", "synthetic", scope):
                        raise ContinuousRuntimeAttemptSourceError(
                            "ATTEMPT_ORIGINAL_DISPATCH_SCOPE_DIFFERS"
                        )
                    dispatches.append((key, claim.record))
                if closure.kind == "expired_unsent":
                    if closure.dispatch_keys != (
                        self._dispatch_key(closure.scope, closure.preparations[0].request),
                    ):
                        raise ContinuousRuntimeAttemptSourceError(
                            "UNSENT_ORIGINAL_DISPATCH_SCOPE_DIFFERS"
                        )
                elif set(keys) != {claim.receipt.committed_head.key_sha256 for claim in claims}:
                    raise ContinuousRuntimeAttemptSourceError(
                        "ATTEMPT_DISPATCH_KEY_INVENTORY_DIFFERS"
                    )
                fresh = self._fresh.get(ref.semantic_sha256)
                if fresh is not None:
                    self.require_prepared(fresh)
                    if (fresh.reference, fresh.source, fresh.closure, fresh.action) != (
                        ref,
                        source,
                        closure,
                        action,
                    ):
                        raise ContinuousRuntimeAttemptSourceError(
                            "ATTEMPT_ORIGINAL_FRESH_SOURCE_DIFFERS"
                        )
                admission_payloads = tuple(
                    graph.raw(ref.object_ref) for ref in closure.admission_records
                )
                descriptor_plan = (
                    None
                    if descriptor is None
                    else cast(Any, self.runtime_sources).prepare_historical_descriptor(
                        closure.descriptor, admit_objects=graph.admit
                    )
                )
                if descriptor_plan is not None:
                    graph.admit(tuple(cast(Any, descriptor_plan).object_refs))
                outcome_plan = (
                    None
                    if closure.outcome_reference is None
                    else self._outcome_reader().prepare(
                        closure.outcome_reference, admit_objects=graph.admit
                    )
                )
                item = _Source(
                    ref,
                    source,
                    closure,
                    cp,
                    action,
                    request,
                    tuple(dispatches),
                    admission_payloads,
                    fresh,
                    descriptor_plan,
                    descriptor,
                    self.dispatch_journal._key_payload(closure.dispatch_keys[0])
                    if closure.kind == "expired_unsent"
                    else None,
                    outcome_plan,
                )
                self._validate_source(item)
                items.append(item)
            return self._own(RuntimeAttemptSourcePlan(references, _Plan(tuple(items))))
        except ContinuousRuntimeAttemptSourceError:
            raise
        except Exception:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_SOURCE_PLANNING_FAILED") from None

    @staticmethod
    def _claims(closure: ContinuousRuntimeAttemptClosure) -> tuple[DailyDispatchClaim, ...]:
        return (
            closure.prior_dispatches
            if closure.kind != "activation"
            else tuple(event.dispatch for event in closure.events if event.dispatch is not None)
        )

    def capture_attempt_sources_in_transaction(
        self,
        connection: Connection,
        plan: RuntimeAttemptSourcePlan,
        *,
        account_id: str,
        budget: RuntimeReadBudget,
    ) -> RuntimeAttemptSourceSnapshot:
        self._require(plan, RuntimeAttemptSourcePlan)
        state = cast(_Plan, plan.state)
        if type(budget) is not RuntimeReadBudget or connection.engine is not self.engine:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_SAME_ENGINE_SHARED_BUDGET_REQUIRED")
        try:
            initial = len(budget.captured)
            provenance = []
            for table in (
                continuous_account_commits,
                daily_runtime_assignments,
                daily_runtime_consumptions,
                daily_runtime_attempt_events,
                daily_runtime_observed_hold_groups,
                phase5_operational_control_transitions,
                phase5_operational_control_completions,
                phase5_operational_control_heads,
            ):
                retained = tuple(
                    item
                    for item in budget.captured
                    if item.table is table and item.account_id == account_id
                )
                if len(retained) > 1:
                    raise ContinuousRuntimeAttemptSourceError(
                        "ATTEMPT_DUPLICATE_ORIGINAL_TABLE_CAPTURE"
                    )
                captured = (
                    retained[0]
                    if retained
                    else capture_runtime_table(
                        connection, table, account_id=account_id, budget=budget
                    )
                )
                if retained:
                    _recheck_table(connection, captured)
                provenance.append(captured)
            c_rows = {row["command_id"]: row for row in provenance[0].rows}
            pool = DetachedJournalCapture(
                max_bytes=MAX_ATTEMPT_OBJECT_BYTES, max_metadata_bytes=MAX_METADATA_BYTES
            )
            charged = (0, 0, 0)
            leases: dict[str, Mapping[str, Any]] = {}
            references, historical, dispatches, descriptors = [], [], [], []
            outcomes = []
            for item in state.sources:
                source, closure, fresh = item.source, item.closure, item.fresh
                if source.account_id != account_id:
                    raise ContinuousRuntimeAttemptSourceError("ATTEMPT_SOURCE_ACCOUNT_DIFFERS")
                raw = self.accounts.capture_reference_in_transaction(
                    connection,
                    scope=closure.scope,
                    command_id=source.coordinator_command_id,
                    source_lease_sha256=source.fence.lease_sha256,
                    journal_pool=pool,
                )
                is_history = raw is not None
                if raw is None:
                    if fresh is None:
                        raise ContinuousRuntimeAttemptSourceError(
                            "ATTEMPT_ACTUAL_PARENT_OR_FRESH_TOKEN_REQUIRED"
                        )
                    self._require(fresh, PreparedContinuousRuntimeAttemptSource)
                    raw = self.accounts.capture_reference_in_transaction(
                        connection,
                        scope=closure.scope,
                        command_id=closure.previous.commit.transition.command_id,
                        source_lease_sha256=source.fence.lease_sha256,
                        journal_pool=pool,
                    )
                    if (
                        raw is None
                        or raw.current.row != fresh.previous.snapshot.row
                        or (
                            self.accounts.capture_current_in_transaction(
                                connection, scope=closure.scope
                            )
                            != raw.current
                        )
                    ):
                        raise ContinuousRuntimeAttemptSourceError(
                            "ATTEMPT_ORIGINAL_CURRENT_C_PREFIX_DIFFERS"
                        )
                    self.daily.recheck_snapshot_in_transaction(
                        connection, fresh.current, fence=source.fence.fence
                    )
                for index in (raw.current, raw.previous):
                    if index is not None and c_rows.get(index.row["command_id"]) != index.row:
                        raise ContinuousRuntimeAttemptSourceError(
                            "ATTEMPT_COHERENT_C_METADATA_DIFFERS"
                        )
                for lease in (raw.lease, raw.previous_lease, raw.source_lease):
                    if lease is None:
                        continue
                    key = str(lease["lease_sha256"])
                    original = leases.get(key)
                    if original is not None:
                        if original != lease:
                            raise ContinuousRuntimeAttemptSourceError(
                                "ATTEMPT_COHERENT_LEASE_DIFFERS"
                            )
                    else:
                        leases[key] = lease
                        budget.charge(
                            1,
                            sum(len(value) for value in lease.values() if type(value) is bytes),
                            sum(
                                len(str(value).encode())
                                for value in lease.values()
                                if value is not None and type(value) is not bytes
                            ),
                        )
                actual_dispatches = tuple(
                    pool.capture(
                        self.dispatch_journal.capture_in_transaction(
                            connection, key, command_id=record.command_id
                        )
                    )
                    for key, record in item.dispatches
                )
                if closure.kind == "expired_unsent":
                    terminal = closure.unsent_dispatch_receipt
                    actual_dispatches = (
                        pool.capture(
                            self.dispatch_journal.capture_in_transaction(
                                connection,
                                closure.dispatch_keys[0],
                                command_id=None if terminal is None else terminal.command_id,
                            )
                        ),
                    )
                descriptor_raw = (
                    None
                    if item.descriptor_plan is None
                    else cast(
                        Any, self.runtime_sources
                    ).capture_historical_descriptor_in_transaction(
                        connection, item.descriptor_plan, budget=budget
                    )
                )
                now = (len(pool.rows), pool.byte_count, pool.metadata_bytes)
                budget.charge(*(new - old for new, old in zip(now, charged, strict=True)))
                charged = now
                outcome_raw = None
                if item.outcome_plan is not None:
                    outcome_raw = self._outcome_reader().capture_in_transaction(
                        connection, item.outcome_plan, budget=budget, journal_pool=pool
                    )
                    charged = (len(pool.rows), pool.byte_count, pool.metadata_bytes)
                references.append(raw)
                historical.append(is_history)
                dispatches.append(actual_dispatches)
                descriptors.append(descriptor_raw)
                outcomes.append(outcome_raw)
            return self._own(
                RuntimeAttemptSourceSnapshot(
                    plan,
                    tuple(budget.captured[initial:]),
                    _Captured(
                        state,
                        tuple(provenance),
                        tuple(references),
                        tuple(historical),
                        tuple(dispatches),
                        tuple(descriptors),
                        tuple(outcomes),
                    ),
                )
            )
        except ContinuousRuntimeAttemptSourceError:
            raise
        except Exception:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_SOURCE_CAPTURE_FAILED") from None

    def _validate_reference(
        self, item: _Source, actual: ResolvedContinuousReference, *, historical: bool
    ) -> None:
        source, closure = item.source, item.closure
        lease, receipt = actual.source_lease, actual.receipt
        if lease is None or (
            lease.semantic_sha256 != source.fence.lease_sha256
            or lease.fence != source.fence.fence
            or lease.policy_sha256 != source.fence.policy_sha256
            or not lease.heartbeat_at
            <= source.fence.validated_at
            <= source.checked_at
            < source.valid_until
            <= source.fence.valid_until
            <= lease.expires_at
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_SOURCE_LEASE_DIFFERS")
        if historical:
            commit, fence = receipt.commit, receipt.fence_reference
            if (
                actual.previous_receipt != closure.previous
                or commit.scope != closure.scope
                or commit.sequence != source.coordinator_sequence
                or commit.transition.command_id != source.coordinator_command_id
                or commit.transition.previous_checkpoint_sha256
                != closure.previous_checkpoint.semantic_sha256
                or commit.request != item.request
                or commit.source_evidence != item.reference
                or commit.transition.source_closure_sha256 != source.semantic_sha256
                or commit.transition.expected_heads != source.heads
                or commit.transition.applied_at != source.checked_at
                or not source.checked_at <= receipt.recorded_at < source.valid_until
                or (fence.owner_id, fence.lease_id, fence.fencing_generation, fence.policy_sha256)
                != (
                    source.fence.fence.owner_id,
                    source.fence.fence.lease_id,
                    source.fence.fence.fencing_generation,
                    source.fence.policy_sha256,
                )
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ACTUAL_PARENT_PUBLICATION_DIFFERS"
                )
        elif item.fresh is None or receipt != closure.previous:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ACTUAL_ORIGINAL_PREVIOUS_DIFFERS")
        else:
            self.require_prepared(item.fresh)

    def _decode(self, row: Mapping[str, Any], kind: type[T]) -> T:
        payload = row["payload"]
        if type(payload) is not bytes or sha256(payload).hexdigest() != row["payload_sha256"]:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_SQL_PAYLOAD_DIFFERS")
        value = self.codec.decode_record(payload, kind)
        if (
            type(value) is not kind
            or self.codec.encode_record(value) != payload
            or (cast(Any, value).semantic_sha256 != row["semantic_sha256"])
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_SQL_CONTENT_DIFFERS")
        return value

    def _validate_admissions(
        self, item: _Source, admissions: tuple[RetainedDailyAdmission, ...]
    ) -> None:
        views = {view.record_sha256: view for view in admissions}
        for ref, payload in zip(
            item.closure.admission_records, item.admission_payloads, strict=True
        ):
            view = views.get(ref.semantic_sha256)
            if view is None or ref.object_ref != ObjectRef(
                view.payload_sha256, len(view.canonical_payload)
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ORIGINAL_ADMISSION_REFERENCE_DIFFERS"
                )
            if payload != view.canonical_payload:
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_ADMISSION_BYTES_DIFFER")
        originals = {
            binding.commitment.commitment_id: binding
            for view in admissions
            for binding in view.bindings
        }
        for binding in item.source.obligations.bindings:
            original = originals.get(binding.commitment.commitment_id)
            if original is None or replace(original, commitment=binding.commitment) != binding:
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_HOLD_LINEAGE_DIFFERS")
        selected = {ref.semantic_sha256 for ref in item.closure.admission_records}
        submitted = {
            submission.order_id: submission for submission in item.checkpoint.state.submissions
        }
        for prep in item.closure.preparations:
            view = views.get(prep.admission_source.semantic_sha256_ref)
            if (
                view is None
                or view.record_sha256 not in selected
                or prep.original_admission != view.admission
                or prep.original_hold not in view.bindings
                or prep.admission_source
                != VenueSourceReference(
                    prep.original_hold.projection,
                    view.record_sha256,
                    ObjectRef(view.payload_sha256, len(view.canonical_payload)),
                )
                or submitted.get(prep.request.submission.order_id) != prep.request.submission
                or prep.request.venue_model != self.runtime_sources.venue_reference
                or prep.request.venue_account_id != self.runtime_sources.venue_model.account_id
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ORIGINAL_PREPARATION_LINEAGE_DIFFERS"
                )

    def _prefixes(
        self,
        state: _Captured,
    ) -> tuple[
        tuple[DailyAttemptEnvelope, ...],
        tuple[DailyObservedHoldGroup, ...],
        dict[str, DailyAttemptPreparation],
    ]:
        tables = {table.table: table for table in state.provenance}
        preparations = {}
        for row in tables[daily_runtime_consumptions].rows:
            prep = self._decode(row, DailyAttemptPreparation)
            hold = prep.original_hold.commitment
            if (row["attempt_id"], row["account_id"], row["intent_id"], row["hold_id"]) != (
                prep.attempt_id,
                prep.request.source_account_id,
                hold.intent_id,
                hold.commitment_id,
            ) or prep.attempt_id in preparations:
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ORIGINAL_CONSUMPTION_INDEX_DIFFERS"
                )
            preparations[prep.attempt_id] = prep
        envelopes = []
        for row in tables[daily_runtime_attempt_events].rows:
            envelope = self._decode(row, DailyAttemptEnvelope)
            event = envelope.event
            if (
                row["attempt_id"],
                row["account_id"],
                row["coordinator_command_id"],
                row["coordinator_sequence"],
                row["sequence"],
                row["event_sha256"],
                row["state"],
                row["previous_event_sha256"],
            ) != (
                event.attempt_id,
                envelope.account_id,
                envelope.coordinator_command_id,
                envelope.coordinator_sequence,
                event.sequence,
                event.semantic_sha256,
                event.state.value,
                event.previous_event_sha256,
            ) or event.attempt_id not in preparations:
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_EVENT_INDEX_DIFFERS")
            envelopes.append(envelope)
        groups = []
        for row in tables[daily_runtime_observed_hold_groups].rows:
            group = self._decode(row, DailyObservedHoldGroup)
            if (row["account_id"], row["coordinator_command_id"], row["coordinator_sequence"]) != (
                group.account_id,
                group.coordinator_command_id,
                group.coordinator_sequence,
            ):
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_OBSERVED_INDEX_DIFFERS")
            groups.append(group)
        return tuple(envelopes), tuple(groups), preparations

    def _validate_prefix(
        self,
        item: _Source,
        *,
        envelopes: tuple[DailyAttemptEnvelope, ...],
        groups: tuple[DailyObservedHoldGroup, ...],
        preparations: dict[str, DailyAttemptPreparation],
        historical: bool,
    ) -> tuple[str, ...]:
        source, closure = item.source, item.closure
        prefix = tuple(
            value for value in envelopes if value.coordinator_sequence < source.coordinator_sequence
        )
        ids = tuple(sorted({value.event.attempt_id for value in prefix}))
        attempts = tuple(
            reduce_daily_attempt(
                preparations[identity],
                tuple(value.event for value in prefix if value.event.attempt_id == identity),
            )
            for identity in ids
        )
        if source.heads.attempt_sha256 != daily_attempt_inventory_sha256(attempts) or (
            source.heads.effect_watermark
            != daily_runtime_effect_watermark(
                attempt_envelopes=prefix,
                observed_groups=tuple(
                    group
                    for group in groups
                    if group.coordinator_sequence < source.coordinator_sequence
                ),
            )
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ACTUAL_HISTORY_HEADS_DIFFER")
        actual = {attempt.attempt_id: attempt for attempt in attempts}
        for prep, event in zip(closure.preparations, closure.events, strict=True):
            prior = actual.get(prep.attempt_id)
            if closure.kind == "pending":
                if prior is not None:
                    raise ContinuousRuntimeAttemptSourceError(
                        "PENDING_ORIGINAL_ATTEMPT_ALREADY_EXISTS"
                    )
                reduce_daily_attempt(prep, (event,))
            elif closure.kind == "activation":
                if (
                    prior is None
                    or prior.preparation != prep
                    or prior.state is not SubmissionAttemptState.PENDING
                ):
                    raise ContinuousRuntimeAttemptSourceError(
                        "ACTIVATION_ORIGINAL_PENDING_HISTORY_DIFFERS"
                    )
                reduce_daily_attempt(prep, (*prior.events, event))
            elif closure.kind == "expired_unsent":
                if (
                    prior is None
                    or prior.preparation != prep
                    or prior.state is not SubmissionAttemptState.PENDING
                    or event.unsent_proof is None
                    or source.accounting_command is None
                    or event.unsent_proof.heads != source.heads
                    or event.unsent_proof.fence != source.fence
                    or event.unsent_proof.checked_at != source.checked_at
                    or any(
                        value.event_id in item.checkpoint.pending_ids
                        and value.knowledge_at <= source.checked_at
                        for value in item.checkpoint.events
                    )
                ):
                    raise ContinuousRuntimeAttemptSourceError(
                        "UNSENT_ORIGINAL_PENDING_PROOF_DIFFERS"
                    )
                if self._dispatch_prefix(closure.dispatch_keys[0], attempts) != (
                    closure.unsent_dispatch_head,
                    closure.unsent_dispatch_receipt,
                ):
                    raise ContinuousRuntimeAttemptSourceError(
                        "UNSENT_ORIGINAL_COMPLETE_DISPATCH_HISTORY_DIFFERS"
                    )
                self._validate_unsent_accounting(
                    item.checkpoint, prior, event.unsent_proof, source.accounting_command
                )
                reduce_daily_attempt(prep, (*prior.events, event))
            elif closure.kind == "outcome":
                if (
                    prior is None
                    or prior.preparation != prep
                    or prior.state
                    not in (
                        SubmissionAttemptState.IN_FLIGHT,
                        SubmissionAttemptState.UNKNOWN,
                    )
                    or event.state
                    is not (
                        SubmissionAttemptState.CONFIRMED
                        if prior.state is SubmissionAttemptState.IN_FLIGHT
                        else SubmissionAttemptState.RESOLVED
                    )
                    or tuple(value.dispatch for value in prior.events if value.dispatch is not None)
                    != closure.prior_dispatches
                ):
                    raise ContinuousRuntimeAttemptSourceError(
                        "OUTCOME_ORIGINAL_UNRESOLVED_HISTORY_DIFFERS"
                    )
                reduce_daily_attempt(prep, (*prior.events, event))
            else:
                if (
                    prior is None
                    or prior.preparation != prep
                    or prior.state is not SubmissionAttemptState.IN_FLIGHT
                ):
                    raise ContinuousRuntimeAttemptSourceError(
                        "UNKNOWN_ORIGINAL_IN_FLIGHT_HISTORY_DIFFERS"
                    )
                claim = next(
                    claim
                    for claim in closure.prior_dispatches
                    if claim.record.preparation.attempt_id == prep.attempt_id
                )
                if prior.events[-1].dispatch != claim:
                    raise ContinuousRuntimeAttemptSourceError(
                        "UNKNOWN_ORIGINAL_DISPATCH_CLAIM_DIFFERS"
                    )
                reduce_daily_attempt(prep, (*prior.events, event))
        retained = tuple(
            sorted(
                (
                    value
                    for value in envelopes
                    if value.coordinator_sequence == source.coordinator_sequence
                ),
                key=lambda value: value.event.attempt_id,
            )
        )
        expected = tuple(
            DailyAttemptEnvelope(
                account_id=source.account_id,
                coordinator_command_id=source.coordinator_command_id,
                coordinator_sequence=source.coordinator_sequence,
                event=event,
                source_ref=item.reference,
            )
            for event in closure.events
        )
        if historical and (
            retained != expected
            or any(preparations.get(prep.attempt_id) != prep for prep in closure.preparations)
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ACTUAL_PARENT_EVENT_GROUP_DIFFERS")
        if not historical and retained:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_UNPUBLISHED_PARENT_HAS_EVENT_ROWS")
        return tuple(
            sorted(
                set(ids)
                | ({prep.attempt_id for prep in closure.preparations} if historical else set())
            )
        )

    def resolve_attempt_sources(
        self,
        snapshot: RuntimeAttemptSourceSnapshot,
        *,
        admissions: tuple[RetainedDailyAdmission, ...],
    ) -> ResolvedRuntimeAttemptSources:
        self._require(snapshot, RuntimeAttemptSourceSnapshot)
        state = cast(_Captured, snapshot.state)
        try:
            for admission in admissions:
                self.daily.require_admission_view(admission)
            envelopes, groups, preparations = self._prefixes(state)
            references, dispatches, selected = [], [], []
            descriptors = []
            outcomes = []
            for item, raw, historical, dispatch_raw, descriptor_raw, outcome_raw in zip(
                state.plan.sources,
                state.references,
                state.historical,
                state.dispatches,
                state.descriptors,
                state.outcomes,
                strict=True,
            ):
                actual = self.accounts.resolve_reference(raw)
                self._validate_source(item)
                self._validate_reference(item, actual, historical=historical)
                self._validate_admissions(item, admissions)
                ids = self._validate_prefix(
                    item,
                    envelopes=envelopes,
                    groups=groups,
                    preparations=preparations,
                    historical=historical,
                )
                qualified = tuple(
                    self.dispatch_journal.resolve_snapshot(raw) for raw in dispatch_raw
                )
                claims = self._claims(item.closure)
                if item.closure.kind == "expired_unsent":
                    (read,) = qualified
                    if read.receipt != item.closure.unsent_dispatch_receipt or (
                        not historical and read.head != item.closure.unsent_dispatch_head
                    ):
                        raise ContinuousRuntimeAttemptSourceError(
                            "UNSENT_ORIGINAL_DISPATCH_JOURNAL_DIFFERS"
                        )
                for read, claim in zip(qualified if claims else (), claims, strict=True):
                    if item.closure.kind == "activation" and not historical:
                        if (
                            item.fresh is None
                            or not item.fresh.dispatch_appends
                            or read.receipt is not None
                        ):
                            raise ContinuousRuntimeAttemptSourceError(
                                "ACTIVATION_ORIGINAL_UNPUBLISHED_DISPATCH_REQUIRED"
                            )
                        if read.head != item.fresh.dispatch_appends[0].request.expected_head or (
                            tuple(append.receipt for append in item.fresh.dispatch_appends)
                            != tuple(claim.receipt for claim in claims)
                        ):
                            raise ContinuousRuntimeAttemptSourceError(
                                "ACTIVATION_ORIGINAL_PREPARED_DISPATCH_DIFFERS"
                            )
                    elif read.receipt != claim.receipt:
                        raise ContinuousRuntimeAttemptSourceError(
                            "ATTEMPT_ACTUAL_DISPATCH_JOURNAL_DIFFERS"
                        )
                descriptor_value = None
                if item.closure.kind == "activation":
                    if (
                        descriptor_raw is None
                        or item.descriptor is None
                        or item.descriptor.assignment_sha256 is None
                    ):
                        raise ContinuousRuntimeAttemptSourceError(
                            "ACTIVATION_DESCRIPTOR_CAPTURE_REQUIRED"
                        )
                    prefix = self.resolve_original_prefix(
                        snapshot,
                        source_reference=item.reference,
                        admissions=admissions,
                        assignment_sha256=item.descriptor.assignment_sha256,
                        control_sha256=item.descriptor.control_sha256,
                    )
                    descriptor_value = cast(
                        Any, self.runtime_sources
                    ).resolve_historical_descriptor(descriptor_raw, prefix=prefix)
                    self._validate_activation(item, prefix, descriptor_value)
                outcome_value = None
                if item.closure.kind == "outcome":
                    if outcome_raw is None:
                        raise ContinuousRuntimeAttemptSourceError(
                            "OUTCOME_ORIGINAL_CAPTURE_REQUIRED"
                        )
                    revision = item.source.heads.control_revision
                    controls = tuple(
                        row
                        for table in state.provenance
                        if table.table is phase5_operational_control_transitions
                        for row in table.rows
                        if row["sequence_number"] == revision
                    )
                    if (revision == 0 and controls) or (revision > 0 and len(controls) != 1):
                        raise ContinuousRuntimeAttemptSourceError(
                            "OUTCOME_ORIGINAL_CONTROL_PREFIX_DIFFERS"
                        )
                    prefix = self.resolve_original_prefix(
                        snapshot,
                        source_reference=item.reference,
                        admissions=admissions,
                        assignment_sha256=item.closure.preparations[
                            0
                        ].original_admission.evidence.assignment.semantic_sha256,
                        control_sha256=None
                        if revision == 0
                        else str(controls[0]["semantic_sha256"]),
                    )
                    outcome_value = self._outcome_reader().resolve(outcome_raw, prefix=prefix)
                    if outcome_value.outcome != item.closure.events[0].outcome:
                        raise ContinuousRuntimeAttemptSourceError(
                            "OUTCOME_ORIGINAL_EVENT_CAPTURE_DIFFERS"
                        )
                source = item.source
                through = (
                    source.coordinator_sequence if historical else source.coordinator_sequence - 1
                )
                for table in state.provenance:
                    name = table.table
                    if name in (
                        daily_runtime_assignments,
                        phase5_operational_control_completions,
                        phase5_operational_control_heads,
                    ):
                        continue
                    if name is continuous_account_commits:
                        chosen = tuple(row for row in table.rows if row["sequence"] <= through)
                        predicates = (name.c.sequence <= through,)
                    elif name is daily_runtime_consumptions:
                        chosen = tuple(row for row in table.rows if row["attempt_id"] in ids)
                        predicates = (name.c.attempt_id.in_(ids),)
                    elif name is phase5_operational_control_transitions:
                        revision = source.heads.control_revision
                        chosen = tuple(
                            row for row in table.rows if row["sequence_number"] <= revision
                        )
                        if tuple(sorted(row["sequence_number"] for row in chosen)) != tuple(
                            range(1, revision + 1)
                        ):
                            raise ContinuousRuntimeAttemptSourceError(
                                "ATTEMPT_ORIGINAL_CONTROL_PREFIX_DIFFERS"
                            )
                        predicates = (name.c.sequence_number <= revision,)
                    else:
                        chosen = tuple(
                            row for row in table.rows if row["coordinator_sequence"] <= through
                        )
                        predicates = (name.c.coordinator_sequence <= through,)
                    selected.append(
                        (RuntimeTableSnapshot(name, table.account_id, chosen), predicates)
                    )
                references.append(actual)
                dispatches.append(qualified)
                descriptors.append(descriptor_value)
                outcomes.append(outcome_value)
            value = self._own(
                ResolvedRuntimeAttemptSources(
                    snapshot,
                    tuple(item.source for item in state.plan.sources),
                    _Resolved(
                        state,
                        tuple(references),
                        tuple(dispatches),
                        tuple(selected),
                        tuple(descriptors),
                        tuple(outcomes),
                    ),
                )
            )
            self._fingerprints[id(value)] = self._fingerprint(value)
            finalize(value, self._fingerprints.pop, id(value), None)
            return value
        except ContinuousRuntimeAttemptSourceError:
            raise
        except Exception:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_SOURCE_RESOLUTION_FAILED") from None

    def _validate_activation(
        self,
        item: _Source,
        prefix: OriginalContinuousRuntimeAttemptPrefix,
        descriptor: object,
    ) -> None:
        self.require_prefix(prefix)
        port = cast(Any, self.runtime_sources).historical_evidence_port(descriptor)
        if (
            port.descriptor != item.descriptor
            or cast(Any, descriptor).receipt != item.closure.descriptor_receipt
        ):
            raise ContinuousRuntimeAttemptSourceError(
                "ACTIVATION_ACTUAL_DESCRIPTOR_RECEIPT_DIFFERS"
            )
        cp, source = item.checkpoint, item.source
        by_id = {attempt.attempt_id: attempt for attempt in prefix.attempts}
        attempts = tuple(by_id[prep.attempt_id] for prep in item.closure.preparations)
        original = attempts[0].preparation.original_admission.decision.batch
        if any(
            attempt.preparation.original_admission.decision.batch.target != original.target
            for attempt in attempts
        ):
            raise ContinuousRuntimeAttemptSourceError("ACTIVATION_COMMON_ORIGINAL_BATCH_REQUIRED")
        snapshot = cp.current.snapshot
        batch = replace(
            original,
            snapshot_sha256=snapshot.semantic_sha256,
            intents=tuple(attempt.preparation.request.submission.intent for attempt in attempts),
        )
        loss, drawdown = continuous_runtime_loss_inputs(cp)
        evidence = port.build(
            snapshot=snapshot,
            batch=batch,
            phase="activation",
            evaluated_at=source.checked_at,
            accepted_intent_ids=dict(cp.accepted).get(batch.target.trigger.execution_session, ()),
            daily_return=loss,
            drawdown=drawdown,
            request_rows=cp.request_rows,
        )
        decision = evaluate_daily_risk(
            port.assignment.policy, snapshot, batch, evidence, source.checked_at
        )
        if not decision.approved:
            raise ContinuousRuntimeAttemptSourceError("ACTIVATION_ACTUAL_RISK_DID_NOT_APPROVE")
        holdings = {
            binding.commitment.commitment_id: binding for binding in prefix.obligations.bindings
        }
        claims = self._claims(item.closure)
        dispatches = tuple(
            prepare_daily_dispatch(
                attempt=attempt,
                activation=prepare_daily_activation(
                    preparation=attempt.preparation,
                    current_hold=holdings[
                        attempt.preparation.original_hold.commitment.commitment_id
                    ],
                    snapshot=snapshot,
                    evidence=evidence,
                    decision=decision,
                    heads=source.heads,
                    fence=source.fence,
                    checked_at=source.checked_at,
                ),
                command_id=canonical_id(
                    "daily-dispatch", source.coordinator_command_id, attempt.attempt_id
                ),
                dispatched_at=source.checked_at,
            )
            for attempt in attempts
        )
        if dispatches != tuple(claim.record for claim in claims):
            raise ContinuousRuntimeAttemptSourceError("ACTIVATION_ORIGINAL_DISPATCH_RISK_DIFFERS")
        prepared = prepare_daily_runtime_activation(
            state=cp.state,
            context=source.context,
            execution_policy=source.execution_policy,
            attempts=attempts,
            dispatches=dispatches,
            accounting=self.runtime_sources.accounting,
        )
        if prepared.command != source.accounting_command or source.valid_until != min(
            record.activation.expires_at for record in dispatches
        ):
            raise ContinuousRuntimeAttemptSourceError(
                "ACTIVATION_CANONICAL_COMMAND_OR_EXPIRY_DIFFERS"
            )

    def _issue_factory_fingerprint(
        self,
        value: ResolvedRuntimeAttemptSources,
        *,
        context: object,
        max_containers: int,
        max_bindings: int,
    ) -> _FactoryAttemptFingerprint | None:
        """Qualify only a registered original HALTED factory's current episode."""
        try:
            source_behavior, root_behavior, root = _factory_fingerprint_behaviors()
        except (_AttemptBehaviorChanged, _AttemptBehaviorUnsupported):
            return None
        if type(self) is not SqlContinuousRuntimeAttemptSources:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FACTORY_ORIGINAL_OWNER_REQUIRED")
        try:
            _factory_fingerprint_methods(self)
        except ContinuousRuntimeAttemptSourceError:
            return None
        root._require_factory_fingerprint_context(
            context,
            source=self,
            value=value,
            max_containers=max_containers,
            max_bindings=max_bindings,
        )
        reserved_containers = (
            _FACTORY_ROOT_CONTAINERS
            + _FACTORY_SOURCE_CONTAINERS
            + source_behavior.containers
            + root_behavior.containers
        )
        reserved_bindings = (
            _FACTORY_ROOT_BINDINGS
            + _FACTORY_SOURCE_BINDINGS
            + source_behavior.bindings
            + root_behavior.bindings
        )
        if reserved_containers >= max_containers or reserved_bindings >= max_bindings:
            return None
        # The successful original traversal visits an outer exact tuple. With an
        # unchanged ABC token this establishes the negative-cache version witness;
        # admission never calls virtual subclass hooks or primes caches itself.
        token = _factory_data._GET_ABC_TOKEN()
        if type(token) is not int:
            return None
        data = _factory_data._try_seal_attempt_data(
            (value,),
            selectors=_FACTORY_DATA_SELECTORS,
            selector_roles=_FACTORY_DATA_ROLES,
            allowed_records=_FACTORY_DATA_RECORDS,
            selector_objects=_FACTORY_DATA_TABLES,
            mapping_token=token,
            max_containers=max_containers - reserved_containers,
            max_bindings=max_bindings - reserved_bindings,
        )
        if data is None:
            return None
        # Tentative raw bindings grant no authority. Unsupported shape therefore
        # falls back without calling custom conversion hooks an extra time. Only
        # this unchanged complete traversal establishes the fresh cache witness.
        self.require_resolved(value)
        if _factory_data._GET_ABC_TOKEN() != token:
            return None
        source_behavior.require()
        root_behavior.require()
        data.require()
        root._require_factory_fingerprint_context(
            context,
            source=self,
            value=value,
            max_containers=max_containers,
            max_bindings=max_bindings,
        )
        proof = _FactoryAttemptFingerprint()
        identity = id(proof)
        registry = _FACTORY_ATTEMPT_PROOFS

        def released(dead: object) -> None:
            original = registry.get(identity)
            if original is not None and original[0] is dead:
                registry.pop(identity, None)

        token_ref = _weakref(proof, released)
        try:
            state = _FactoryFingerprintState(
                _weakref(self),
                _weakref(context),
                current_thread(),
                value,
                self._fingerprints[id(value)],
                data,
                _factory_fingerprint_data_fields(data),
                source_behavior,
                root_behavior,
                root,
            )
            registry[identity] = (token_ref, state)
            data.require()
            source_behavior.require()
            root_behavior.require()
            root._require_factory_fingerprint_context(
                context,
                source=self,
                value=value,
                max_containers=max_containers,
                max_bindings=max_bindings,
            )
            return proof
        except BaseException:
            registry.pop(identity, None)
            raise

    def _require_resolved_for_factory(
        self,
        value: ResolvedRuntimeAttemptSources,
        *,
        proof: object,
        use: object,
    ) -> None:
        root = _FACTORY_FINGERPRINT_RUNTIME.get("module")
        try:
            source_behavior, root_behavior, root = _factory_fingerprint_behaviors()
            _factory_fingerprint_methods(self)
            original = _FACTORY_ATTEMPT_PROOFS.get(id(proof))
            if (
                type(proof) is not _FactoryAttemptFingerprint
                or original is None
                or original[0]() is not proof
            ):
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FACTORY_ORIGINAL_PROOF_REQUIRED")
            state = original[1]
            context = state.context()
            if (
                state.owner() is not self
                or state.value is not value
                or context is None
                or state.thread is not current_thread()
                or state.source_behavior is not source_behavior
                or state.root_behavior is not root_behavior
                or state.root_module is not root
            ):
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FACTORY_ORIGINAL_PROOF_REQUIRED")
            root._begin_factory_fingerprint_use(
                use,
                context=context,
                source=self,
                value=value,
                proof=proof,
            )
            # Keep the preceding original owner/reference/descriptor/outcome
            # guards in exactly the public method's order. Only its final content
            # fingerprint is replaced by the admitted original-data proof.
            self._require(value, ResolvedRuntimeAttemptSources)
            resolved = cast(_Resolved, value.state)
            for reference in resolved.references:
                self.accounts.require_reference(reference)
            for descriptor in resolved.descriptors:
                if descriptor is not None:
                    cast(Any, self.runtime_sources).require_historical_descriptor(descriptor)
            for outcome in resolved.outcomes:
                if outcome is not None:
                    self._outcome_reader().require_resolved(outcome)
            source_behavior.require()
            root_behavior.require()
            _factory_fingerprint_methods(self)
            if self._fingerprints.get(id(value)) is not state.fingerprint or any(
                actual is not before
                for actual, before in zip(
                    _factory_fingerprint_data_fields(state.data), state.data_fields, strict=True
                )
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ORIGINAL_RESOLVED_CONTENT_CHANGED"
                )
            state.data.require()
            root._end_factory_fingerprint_use(
                use,
                context=context,
                source=self,
                value=value,
                proof=proof,
            )
        except BaseException:
            if root is not None:
                with suppress(BaseException):
                    callback, code = _FACTORY_FINGERPRINT_RUNTIME["_fail_factory_fingerprint_use"]
                    if type(callback) is FunctionType and callback.__code__ is code:
                        callback(use, source=self, value=value)
            raise

    def _retire_factory_fingerprint(self, proof: object, *, context: object) -> None:
        original = _FACTORY_ATTEMPT_PROOFS.get(id(proof))
        if (
            type(proof) is not _FactoryAttemptFingerprint
            or original is None
            or original[0]() is not proof
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FACTORY_ORIGINAL_PROOF_REQUIRED")
        state = original[1]
        if state.owner() is not self or state.context() is not context:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FACTORY_ORIGINAL_PROOF_REQUIRED")
        # Retirement may follow a failed data/method/borrow check. Once the exact
        # source/context is established, a root error cannot strand that graph.
        try:
            callback, code = _FACTORY_FINGERPRINT_RUNTIME["_retire_factory_fingerprint_context"]
            if type(callback) is not FunctionType or callback.__code__ is not code:
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FACTORY_RETIREMENT_CHANGED")
            callback(context, source=self, value=state.value, proof=proof)
        finally:
            _FACTORY_ATTEMPT_PROOFS.pop(id(proof), None)

    def require_resolved(self, value: ResolvedRuntimeAttemptSources) -> None:
        self._require(value, ResolvedRuntimeAttemptSources)
        state = cast(_Resolved, value.state)
        for reference in state.references:
            self.accounts.require_reference(reference)
        for descriptor in state.descriptors:
            if descriptor is not None:
                cast(Any, self.runtime_sources).require_historical_descriptor(descriptor)
        for outcome in state.outcomes:
            if outcome is not None:
                self._outcome_reader().require_resolved(outcome)
        if self._fingerprints.get(id(value)) != self._fingerprint(value):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_RESOLVED_CONTENT_CHANGED")

    def require_same_capture(
        self,
        original: ResolvedRuntimeAttemptSources,
        fresh: RuntimeAttemptSourceSnapshot,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        """Compare actual complete capture inputs without replay or a new source token."""
        if type(comparison) is not ContinuousCaptureComparison:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_EXACT_COMPARISON_REQUIRED")
        self._require(original, ResolvedRuntimeAttemptSources)
        old = original.snapshot
        for snapshot in (old, fresh):
            self._require(snapshot, RuntimeAttemptSourceSnapshot)
            self._require(snapshot.plan, RuntimeAttemptSourcePlan)
            if (
                type(snapshot.state) is not _Captured
                or type(snapshot.plan.state) is not _Plan
                or snapshot.state.plan is not snapshot.plan.state
            ):
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_CAPTURE_PLAN_DIFFERS")
        resolved = cast(_Resolved, original.state)
        before, after = cast(_Captured, old.state), cast(_Captured, fresh.state)
        if type(resolved) is not _Resolved or resolved.captured is not before:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_RESOLVED_CAPTURE_DIFFERS")
        comparison.data(old.plan.references, fresh.plan.references)
        _require_same_runtime_tables(old.tables, fresh.tables, comparison=comparison)
        _require_same_runtime_tables(before.provenance, after.provenance, comparison=comparison)
        comparison.data(before.historical, after.historical)
        for value, source in comparison.pairs(
            original.sources, tuple(item.source for item in before.plan.sources)
        ):
            comparison.identity(value, source)
        for old_source, fresh_source in comparison.pairs(before.plan.sources, after.plan.sources):
            if type(old_source) is not _Source or type(fresh_source) is not _Source:
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_EXACT_SOURCE_PLAN_REQUIRED")
            if (
                type(old_source.source) is not RuntimeAttemptAccountingSource
                or type(fresh_source.source) is not RuntimeAttemptAccountingSource
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_EXACT_ACCOUNTING_SOURCE_REQUIRED"
                )
            comparison.data(
                (
                    old_source.reference,
                    tuple(
                        getattr(old_source.source, f.name)
                        for f in fields(RuntimeAttemptAccountingSource)
                    ),
                    old_source.closure,
                    old_source.checkpoint,
                    old_source.action,
                    old_source.request,
                    old_source.dispatches,
                    old_source.admission_payloads,
                    old_source.descriptor,
                    old_source.unsent_key_payload,
                ),
                (
                    fresh_source.reference,
                    tuple(
                        getattr(fresh_source.source, f.name)
                        for f in fields(RuntimeAttemptAccountingSource)
                    ),
                    fresh_source.closure,
                    fresh_source.checkpoint,
                    fresh_source.action,
                    fresh_source.request,
                    fresh_source.dispatches,
                    fresh_source.admission_payloads,
                    fresh_source.descriptor,
                    fresh_source.unsent_key_payload,
                ),
            )
            comparison.identity(old_source.fresh, fresh_source.fresh)
            if old_source.fresh is not None:
                self._require(old_source.fresh, PreparedContinuousRuntimeAttemptSource)
            for old_plan, new_plan in (
                (old_source.descriptor_plan, fresh_source.descriptor_plan),
                (old_source.outcome_plan, fresh_source.outcome_plan),
            ):
                if (old_plan is None) != (new_plan is None):
                    raise ContinuousRuntimeAttemptSourceError(
                        "ATTEMPT_CAPTURE_PLAN_INVENTORY_DIFFERS"
                    )
        for old_reference, fresh_reference in comparison.pairs(before.references, after.references):
            self.accounts.require_same_reference_capture(
                old_reference, fresh_reference, comparison=comparison
            )
        for left_group, right_group in comparison.pairs(before.dispatches, after.dispatches):
            for old_dispatch, fresh_dispatch in comparison.pairs(left_group, right_group):
                self.dispatch_journal.require_same_capture(
                    old_dispatch, fresh_dispatch, comparison=comparison
                )
        for old_descriptor, fresh_descriptor in comparison.pairs(
            before.descriptors, after.descriptors
        ):
            if old_descriptor is None or fresh_descriptor is None:
                comparison.identity(old_descriptor, fresh_descriptor)
            else:
                cast(Any, self.runtime_sources).require_same_historical_capture(
                    old_descriptor, fresh_descriptor, comparison=comparison
                )
        for old_outcome, fresh_outcome in comparison.pairs(before.outcomes, after.outcomes):
            if old_outcome is None or fresh_outcome is None:
                comparison.identity(old_outcome, fresh_outcome)
            else:
                self._outcome_reader().require_same_capture(
                    old_outcome, fresh_outcome, comparison=comparison
                )
        # Keep source-to-nested-plan linkage exact; lower readers own each plan.
        for state in (before, after):
            for item, descriptor, outcome in zip(
                state.plan.sources, state.descriptors, state.outcomes, strict=True
            ):
                if (
                    (descriptor is None and item.descriptor_plan is not None)
                    or (
                        descriptor is not None
                        and getattr(descriptor, "plan", None) is not item.descriptor_plan
                    )
                    or (outcome is None and item.outcome_plan is not None)
                    or (
                        outcome is not None
                        and getattr(outcome, "plan", None) is not item.outcome_plan
                    )
                ):
                    raise ContinuousRuntimeAttemptSourceError("ATTEMPT_CAPTURE_PLAN_LINK_CHANGED")
        self._require(original, ResolvedRuntimeAttemptSources)
        for snapshot in (old, fresh):
            self._require(snapshot, RuntimeAttemptSourceSnapshot)
            self._require(snapshot.plan, RuntimeAttemptSourcePlan)

    def _recheck_original(
        self,
        connection: Connection,
        value: ResolvedRuntimeAttemptSources,
        *,
        after_publication: bool = False,
    ) -> _Resolved:
        self._require(value, ResolvedRuntimeAttemptSources)
        if connection.engine is not self.engine:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_SAME_ENGINE_REQUIRED")
        state = cast(_Resolved, value.state)
        for snapshot, predicates in state.selected:
            bounded = (
                sa.select(*snapshot.table.primary_key.columns)
                .where(snapshot.table.c.account_id == snapshot.account_id, *predicates)
                .limit(MAX_ROWS + 1)
                .subquery()
            )
            if connection.scalar(sa.select(sa.func.count()).select_from(bounded)) != len(
                snapshot.rows
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ORIGINAL_PREFIX_INVENTORY_CHANGED"
                )
            _recheck_table(connection, snapshot, exact_inventory=False)
        for item, reference, reads, historical, descriptor, outcome in zip(
            state.captured.plan.sources,
            state.references,
            state.dispatches,
            state.captured.historical,
            state.descriptors,
            state.outcomes,
            strict=True,
        ):
            self.accounts.recheck_reference_in_transaction(connection, reference)
            if after_publication and not historical and item.closure.kind == "activation":
                if item.fresh is None:
                    raise ContinuousRuntimeAttemptSourceError(
                        "ACTIVATION_ORIGINAL_DISPATCH_PREPARATION_MISSING"
                    )
                self._require(item.fresh, PreparedContinuousRuntimeAttemptSource)
                for index, append in enumerate(item.fresh.dispatch_appends):
                    self.dispatch_journal.recheck_prepared_append_in_transaction(
                        connection,
                        append,
                        require_current_head=index == len(item.fresh.dispatch_appends) - 1,
                    )
            else:
                for read in reads:
                    if (
                        historical
                        and item.closure.kind == "expired_unsent"
                        and read.snapshot.stream is None
                    ):
                        self._recheck_original_empty_dispatch_prefix(connection, item, read)
                        continue
                    self.dispatch_journal.recheck_in_transaction(
                        connection,
                        read,
                        require_current_head=not historical
                        and item.closure.kind == "expired_unsent",
                    )
            if descriptor is not None:
                cast(Any, self.runtime_sources).recheck_historical_descriptor_in_transaction(
                    connection, descriptor
                )
            if outcome is not None:
                self._outcome_reader().recheck_in_transaction(connection, outcome)
        return state

    def _recheck_original_empty_dispatch_prefix(
        self, connection: Connection, item: _Source, read: ResolvedJournalRead
    ) -> None:
        """An authenticated historical empty prefix owns no future journal rows.

        Its actual original C/B prefix is rechecked by the enclosing method. A
        newly created stream grants no financial or fresh no-dispatch authority;
        only its bounded immutable key identity can apply to this empty prefix.
        Fresh unsent publication always uses the normal exact current-head check.
        """
        if (
            item.closure.unsent_dispatch_head != read.head
            or read.head.sequence != 0
            or read.receipt is not None
            or item.closure.unsent_dispatch_receipt is not None
            or item.unsent_key_payload is None
        ):
            raise ContinuousRuntimeAttemptSourceError("UNSENT_ORIGINAL_EMPTY_PREFIX_DIFFERS")
        row = _journal_stream_row(connection, read.head.key_sha256)
        orphaned = (
            _journal_has_records(connection, read.head.key_sha256)
            if row is None or row["last_sequence"] == 0
            else False
        )
        if orphaned or (
            row is not None
            and (
                row["key_sha256"] != read.head.key_sha256
                or row["key_payload"] != item.unsent_key_payload
                or type(row["last_sequence"]) is not int
                or not 0 <= row["last_sequence"] <= MAX_SEQUENCE
                or (
                    row["last_sequence"] == 0 and row["last_entry_sha256"] != read.head.entry_sha256
                )
            )
        ):
            raise ContinuousRuntimeAttemptSourceError("UNSENT_HISTORICAL_STREAM_IDENTITY_CHANGED")

    def resolve_original_prefix(
        self,
        snapshot: RuntimeAttemptSourceSnapshot,
        *,
        source_reference: ContinuousEvidenceRef,
        admissions: tuple[RetainedDailyAdmission, ...],
        assignment_sha256: str,
        control_sha256: str | None,
    ) -> OriginalContinuousRuntimeAttemptPrefix:
        """Select original provenance before descriptor checks and B's later complete replay.

        The requested digests only select original retained rows; they cannot
        manufacture an assignment, control state, financial prefix or risk pass.
        """
        self._require(snapshot, RuntimeAttemptSourceSnapshot)
        state = cast(_Captured, snapshot.state)
        matches = [
            (item, raw, historical)
            for item, raw, historical in zip(
                state.plan.sources, state.references, state.historical, strict=True
            )
            if item.reference == source_reference
        ]
        if len(matches) != 1:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_PREFIX_SOURCE_REQUIRED")
        item, raw, historical = matches[0]
        actual = self.accounts.resolve_reference(raw)
        self._validate_reference(item, actual, historical=historical)
        for admission in admissions:
            self.daily.require_admission_view(admission)
        self._validate_admissions(item, admissions)
        source, cp = item.source, item.checkpoint
        through = source.coordinator_sequence - 1
        if cp.semantic_sha256 != item.closure.previous_checkpoint.semantic_sha256 or (
            source.state != cp.state
            or tuple(binding.commitment for binding in source.obligations.bindings)
            != tuple(sorted(cp.state.commitments, key=lambda hold: hold.commitment_id))
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_PREFIX_CHECKPOINT_DIFFERS")
        envelopes, groups, preparations = self._prefixes(state)
        prefix = tuple(item for item in envelopes if item.coordinator_sequence <= through)
        ids = tuple(sorted({item.event.attempt_id for item in prefix}))
        attempts = tuple(
            reduce_daily_attempt(
                preparations[identity],
                tuple(item.event for item in prefix if item.event.attempt_id == identity),
            )
            for identity in ids
        )
        observed = tuple(group for group in groups if group.coordinator_sequence <= through)
        if source.heads.attempt_sha256 != daily_attempt_inventory_sha256(attempts) or (
            source.heads.effect_watermark
            != daily_runtime_effect_watermark(attempt_envelopes=prefix, observed_groups=observed)
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_PREFIX_HISTORY_DIFFERS")
        rows = {table.table: _typed_rows(table) for table in state.provenance}
        assignments = []
        previous_digest = None
        for generation, row in enumerate(rows[daily_runtime_assignments], 1):
            assignment = self._decode(row, RuntimeRiskAssignment)
            command = self.codec.decode_record(row["command_payload"], RuntimeAssignmentCommand)
            if (
                (
                    assignment.account_id,
                    assignment.generation,
                    assignment.previous_assignment_sha256,
                    row["generation"],
                    row["previous_sha256"],
                )
                != (source.account_id, generation, previous_digest, generation, previous_digest)
                or assignment.account_binding_sha256 != item.closure.scope.account_binding_sha256
                or (
                    self.codec.encode_record(command) != row["command_payload"]
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
                        source.account_id,
                        previous_digest,
                        assignment.semantic_sha256,
                    )
                    or not command.requested_at <= row["recorded_at"] < command.expires_at
                )
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ORIGINAL_ASSIGNMENT_CHAIN_DIFFERS"
                )
            assignments.append((assignment, row))
            previous_digest = assignment.semantic_sha256
        matched = [
            (value, row) for value, row in assignments if value.semantic_sha256 == assignment_sha256
        ]
        if len(matched) != 1 or matched[0][1]["recorded_at"] > source.checked_at:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_ASSIGNMENT_PREFIX_MISSING")
        assignment = matched[0][0]
        control_heads = rows[phase5_operational_control_heads]
        if len(control_heads) > 1:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_CONTROL_HEAD_INVENTORY_DIFFERS")
        controls = _verified_history_from_rows(
            account_id=source.account_id,
            transition_rows=rows[phase5_operational_control_transitions],
            completion_rows=_completion_rows_index(rows[phase5_operational_control_completions]),
            head_row=next(iter(control_heads), None),
        )
        revision = source.heads.control_revision
        if not 0 <= revision <= len(controls):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_CONTROL_PREFIX_MISSING")
        control = None if revision == 0 else controls[revision - 1].transition
        if (None if control is None else control.semantic_sha256) != control_sha256 or (
            control is not None and control.decided_at > source.checked_at
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_CONTROL_PREFIX_DIFFERS")
        selected = []
        predicates: tuple[Any, ...]
        for table in state.provenance:
            name = table.table
            if name is phase5_operational_control_heads:
                continue
            if name is continuous_account_commits:
                chosen = tuple(row for row in table.rows if row["sequence"] <= through)
                predicates = (name.c.sequence <= through,)
            elif name is daily_runtime_assignments:
                chosen = tuple(
                    row for row in table.rows if row["generation"] <= assignment.generation
                )
                predicates = (name.c.generation <= assignment.generation,)
            elif name is daily_runtime_consumptions:
                chosen = tuple(row for row in table.rows if row["attempt_id"] in ids)
                predicates = (name.c.attempt_id.in_(ids),)
            elif name is phase5_operational_control_transitions:
                chosen = tuple(row for row in table.rows if row["sequence_number"] <= revision)
                predicates = (name.c.sequence_number <= revision,)
            elif name is phase5_operational_control_completions:
                chosen = tuple(
                    row
                    for row, typed in zip(table.rows, rows[name], strict=True)
                    if typed["head_sequence_number"] <= revision
                    and typed["observed_at"] <= source.checked_at
                )
                predicates = (
                    name.c.head_sequence_number <= revision,
                    name.c.observed_at <= source.checked_at,
                )
            else:
                chosen = tuple(row for row in table.rows if row["coordinator_sequence"] <= through)
                predicates = (name.c.coordinator_sequence <= through,)
            selected.append((RuntimeTableSnapshot(name, table.account_id, chosen), predicates))
        value = self._own(
            OriginalContinuousRuntimeAttemptPrefix(
                actual,
                cp,
                source,
                admissions,
                source.obligations,
                attempts,
                prefix,
                observed,
                assignment,
                control,
                through,
                tuple(selected),
                state,
                self._seal,
            )
        )
        self._fingerprints[id(value)] = self._prefix_fingerprint(value)
        finalize(value, self._fingerprints.pop, id(value), None)
        return value

    @staticmethod
    def _prefix_fingerprint(value: OriginalContinuousRuntimeAttemptPrefix) -> str:
        return content_digest(
            (
                value.reference.receipt,
                value.checkpoint,
                value.source,
                tuple((view.canonical_payload, view.bindings) for view in value.admissions),
                value.obligations,
                value.attempts,
                value.attempt_envelopes,
                value.observed_groups,
                value.assignment,
                None if value.control is None else value.control.semantic_sha256,
                value.through_coordinator_sequence,
                detached_journal_value(
                    tuple(
                        (str(table.table.name), table.account_id, table.rows)
                        for table, _ in value.selected
                    )
                ),
            )
        )

    def require_prefix(self, value: OriginalContinuousRuntimeAttemptPrefix) -> None:
        self._require(value, OriginalContinuousRuntimeAttemptPrefix)
        self.accounts.require_reference(value.reference)
        for admission in value.admissions:
            self.daily.require_admission_view(admission)
        if self._fingerprints.get(id(value)) != self._prefix_fingerprint(value):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_ORIGINAL_PREFIX_CONTENT_CHANGED")

    def recheck_prefix_in_transaction(
        self,
        connection: Connection,
        value: OriginalContinuousRuntimeAttemptPrefix,
    ) -> None:
        self._require(value, OriginalContinuousRuntimeAttemptPrefix)
        if connection.engine is not self.engine:
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_SAME_ENGINE_REQUIRED")
        self.accounts.recheck_reference_in_transaction(connection, value.reference)
        for table, predicates in value.selected:
            bounded = (
                sa.select(*table.table.primary_key.columns)
                .where(table.table.c.account_id == table.account_id, *predicates)
                .limit(MAX_ROWS + 1)
                .subquery()
            )
            if connection.scalar(sa.select(sa.func.count()).select_from(bounded)) != len(
                table.rows
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ORIGINAL_PREFIX_INVENTORY_CHANGED"
                )
            _recheck_table(connection, table, exact_inventory=False)

    def recheck_attempt_sources_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedRuntimeAttemptSources,
    ) -> None:
        state = self._recheck_original(connection, resolved)
        for item, reference, historical in zip(
            state.captured.plan.sources, state.references, state.captured.historical, strict=True
        ):
            if historical:
                continue
            if item.fresh is None:
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FRESH_TOKEN_MISSING")
            self._require(item.fresh, PreparedContinuousRuntimeAttemptSource)
            if (
                self.accounts.capture_current_in_transaction(connection, scope=item.closure.scope)
                != reference.snapshot.current
            ):
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FRESH_CURRENT_C_CHANGED")
            self.daily.recheck_snapshot_in_transaction(
                connection, item.fresh.current, fence=item.source.fence.fence
            )

    def recheck_attempt_sources_after_publication_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedRuntimeAttemptSources,
        *,
        prepared_account: object,
        account_receipt: object,
    ) -> None:
        self._require(resolved, ResolvedRuntimeAttemptSources)
        if (
            type(prepared_account) is not PreparedContinuousCommit
            or type(account_receipt) is not ContinuousAccountReceipt
        ):
            raise ContinuousRuntimeAttemptSourceError("ATTEMPT_EXACT_ACCOUNT_PUBLICATION_REQUIRED")
        self.accounts.require_committed_in_transaction(
            connection, prepared=prepared_account, receipt=account_receipt
        )
        state = self._recheck_original(connection, resolved, after_publication=True)
        commit, fence = account_receipt.commit, account_receipt.fence_reference
        for item, reference, historical in zip(
            state.captured.plan.sources, state.references, state.captured.historical, strict=True
        ):
            if historical:
                continue
            if item.fresh is None:
                raise ContinuousRuntimeAttemptSourceError("ATTEMPT_FRESH_TOKEN_MISSING")
            self._require(item.fresh, PreparedContinuousRuntimeAttemptSource)
            source, closure = item.source, item.closure
            if (
                prepared_account.previous is None
                or prepared_account.previous.receipt != reference.receipt
                or commit.scope != closure.scope
                or commit.sequence != source.coordinator_sequence
                or commit.previous_commit_sha256 != reference.snapshot.current.row["commit_sha256"]
                or commit.transition.command_id != source.coordinator_command_id
                or commit.transition.previous_checkpoint_sha256
                != closure.previous_checkpoint.semantic_sha256
                or commit.request != item.request
                or commit.source_evidence != item.reference
                or commit.transition.source_closure_sha256 != item.reference.semantic_sha256
                or commit.transition.expected_heads != source.heads
                or commit.transition.applied_at != source.checked_at
                or not source.checked_at <= account_receipt.recorded_at < source.valid_until
                or (fence.owner_id, fence.lease_id, fence.fencing_generation, fence.policy_sha256)
                != (
                    source.fence.fence.owner_id,
                    source.fence.fence.lease_id,
                    source.fence.fence.fencing_generation,
                    source.fence.policy_sha256,
                )
            ):
                raise ContinuousRuntimeAttemptSourceError(
                    "ATTEMPT_ACTUAL_PENDING_PUBLICATION_DIFFERS"
                )

    def resolve_committed_attempt_sources(
        self,
        original: ResolvedRuntimeAttemptSources,
        *,
        publication: ResolvedContinuousReference,
    ) -> ResolvedCommittedContinuousRuntimeAttemptSources:
        """Bind an original prepared source to separately read actual C metadata.

        The caller captures that metadata after the outer COMMIT. This reader
        proves only the immutable source/publication relationship; the original
        publisher must separately establish successful COMMIT and fresh delivery
        permission. Historical restoration cannot replace the original source.
        """
        self.require_resolved(original)
        self.accounts.require_reference(publication)
        state = cast(_Resolved, original.state)
        fresh = tuple(
            item
            for item, historical in zip(
                state.captured.plan.sources, state.captured.historical, strict=True
            )
            if not historical
        )
        if len(fresh) != 1 or fresh[0].fresh is None:
            raise ContinuousRuntimeAttemptSourceError(
                "ATTEMPT_ORIGINAL_PREPUBLICATION_SOURCE_REQUIRED"
            )
        self.require_prepared(fresh[0].fresh)
        self._validate_reference(fresh[0], publication, historical=True)
        return self._own(
            ResolvedCommittedContinuousRuntimeAttemptSources(original, publication, self._seal)
        )

    def require_committed_attempt_sources(
        self, value: ResolvedCommittedContinuousRuntimeAttemptSources
    ) -> None:
        """Authenticate the complete original detached dependency graph outside SQL."""
        self._require(value, ResolvedCommittedContinuousRuntimeAttemptSources)
        self.require_resolved(value.original)
        self.accounts.require_reference(value.publication)

    def recheck_committed_attempt_sources_in_transaction(
        self,
        connection: Connection,
        value: ResolvedCommittedContinuousRuntimeAttemptSources,
    ) -> None:
        """Read-only original dependency check, allowing subsequent immutable heads.

        This deliberately grants no current account readiness. The publisher's
        separate one-use delivery boundary must verify its exact poststate,
        current controls/fence/deadlines, and successful original COMMIT.
        """
        self._require(value, ResolvedCommittedContinuousRuntimeAttemptSources)
        self._recheck_original(connection, value.original, after_publication=True)
        self.accounts.recheck_reference_in_transaction(connection, value.publication)


# Fixed projection roles distinguish structural owner wrappers from data actually
# visited by detached_journal_value. Equal types in converted data still receive
# their complete ordinary dataclass traversal instead of these selectors.
_FACTORY_DATA_SELECTORS = (
    (ResolvedRuntimeAttemptSources, ("sources", "state")),
    (_Resolved, ("captured", "dispatches")),
    (_Captured, ("plan", "provenance")),
    (_Plan, ("sources",)),
    (
        _Source,
        (
            "reference",
            "closure",
            "checkpoint",
            "action",
            "request",
            "dispatches",
            "admission_payloads",
            "descriptor",
            "unsent_key_payload",
        ),
    ),
    (RuntimeTableSnapshot, ("table", "account_id", "rows")),
    (sa.Table, ("name",)),
)
_FACTORY_DATA_ROLES = (
    (ResolvedRuntimeAttemptSources, (True, False)),
    (_Resolved, (False, True)),
    (_Captured, (False, False)),
    (_Plan, (False,)),
    (_Source, (True,) * 9),
    (RuntimeTableSnapshot, (False, True, True)),
    (sa.Table, (False,)),
)

_FACTORY_DOMAIN_RECORDS = tuple(
    value
    for module_name, module in tuple(sys.modules.items())
    if module_name.startswith("packages.domain.") and type(module) is ModuleType
    for value in tuple(vars(module).values())
    if (type(value) is type or type(value) is EnumType)
    and type.__getattribute__(value, "__module__") == module_name
)
_FACTORY_DATA_RECORDS = (
    *_FACTORY_DOMAIN_RECORDS,
    ResolvedRuntimeAttemptSources,
    _Resolved,
    _Captured,
    _Plan,
    _Source,
    RuntimeTableSnapshot,
    sa.Table,
    RuntimeAttemptAccountingSource,
    ResolvedJournalRead,
    JournalReadSnapshot,
    _FactoryReceiptRows,
)
_FACTORY_DATA_TABLES = (
    continuous_account_commits,
    daily_runtime_assignments,
    daily_runtime_consumptions,
    daily_runtime_attempt_events,
    daily_runtime_observed_hold_groups,
    phase5_operational_control_transitions,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
)
_FACTORY_SOURCE_METHODS = (
    "_issue_factory_fingerprint",
    "_require_resolved_for_factory",
    "_retire_factory_fingerprint",
    "require_resolved",
    "_require",
    "_require_bindings",
    "_binding_values",
    "_outcome_reader",
    "_fingerprint",
)
try:
    _FACTORY_FINGERPRINT_RUNTIME["source"] = _capture_attempt_behavior(
        functions=cast(
            tuple[FunctionType, ...],
            (
                *tuple(
                    getattr(SqlContinuousRuntimeAttemptSources, name)
                    for name in _FACTORY_SOURCE_METHODS
                ),
                _factory_fingerprint_behaviors,
                _factory_fingerprint_data_fields,
                _factory_fingerprint_methods,
                _register_factory_fingerprint_runtime,
                _FactoryFingerprintState.__init__,
                current_thread,
                suppress.__init__,
                suppress.__enter__,
                suppress.__exit__,
                _factory_data._try_seal_attempt_data,
                _factory_data._class_attribute,
                _factory_data._class_metadata,
                _factory_data._same,
                _factory_data._runtime,
                _factory_data._supported_runtime,
                _factory_data._AttemptDataSeal.require,
                _factory_data._AttemptDataSeal.__init__,
                _factory_data._MappingCacheSeal.require,
                _factory_data._MappingCacheSeal.__init__,
            ),
        ),
        modules=(sys.modules[__name__], _factory_data),
        classes=(
            SqlContinuousRuntimeAttemptSources,
            suppress,
            _FactoryAttemptFingerprint,
            _FactoryFingerprintState,
            _factory_data._AttemptDataSeal,
            _factory_data._MappingCacheSeal,
        ),
    )
except _AttemptBehaviorUnsupported:
    _FACTORY_FINGERPRINT_RUNTIME["source"] = None
