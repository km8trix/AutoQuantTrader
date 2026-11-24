"""Detached clock/calendar/local-venue evidence; no provider quota or delivery."""

import hashlib
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from typing import Any, Literal, TypeVar, cast
from weakref import WeakValueDictionary, finalize

from sqlalchemy import Connection, Engine

from packages.adapters.runtime_clock_evidence import RuntimeClockSampler, SampledRuntimeClock
from packages.application.causal_engine import continuous_request_budget_available
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import ContinuousEngineInputs
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountReceipt,
    ContinuousEvidenceRef,
)
from packages.domain.daily_attempt import reduce_daily_attempt
from packages.domain.daily_attempt_contracts import CanonicalDailyAttempt
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalHead,
    JournalKey,
    JournalRecord,
)
from packages.domain.engine_contracts import DailyIntentBatch
from packages.domain.identifiers import canonical_id
from packages.domain.personal_contracts import content_digest, require_utc
from packages.domain.research_job_contracts import (
    ResearchArtifactStore,
    ResearchRecordCodec,
    require_identifier,
)
from packages.domain.runtime_operating_contracts import (
    CLOCK_SCHEMA,
    OPERATING_PROFILE,
    RuntimeClockObservation,
    RuntimeClockReference,
    RuntimeOperatingFact,
)
from packages.domain.stateful_venue_contracts import VenueSourceReference
from packages.persistence.continuous_account import (
    ContinuousIndexSnapshot,
    ResolvedContinuousAccount,
    SqlContinuousAccount,
)
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.daily_runtime_risk import (
    ResolvedDailyRuntimeSnapshot,
    RuntimeReadBudget,
    RuntimeTableSnapshot,
    SqlDailyRuntimeRisk,
    capture_runtime_table,
    daily_attempt_inventory_sha256,
)
from packages.persistence.durable_journal import (
    JournalReadSnapshot,
    PreparedJournalAppend,
    ResolvedJournalRead,
    SqlDurableJournal,
)

T = TypeVar("T")

_CLOCK_REASONS = {
    reason: "STANDARD_CLOCK_" + reason.upper()
    for reason in (
        "monotonic_regression",
        "sampling_timeout",
        "utc_regression",
        "utc_monotonic_disagreement",
        "epoch_changed",
        "suspend_or_cadence_gap",
        "future_sample",
        "sample_stale",
        "source_clock_disagreement",
        "source_changed",
        "offset_blocked",
        "offset_warning",
        "clock_or_source_unavailable",
        "source_unavailable",
        "fault_latched_rearm_required",
        "startup_qualifying",
        "within_limit",
    )
}


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedRuntimeClockAppend:
    reference: RuntimeClockReference
    append: PreparedJournalAppend


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RuntimeOperatingPlan:
    clock_reference: RuntimeClockReference
    clock: RuntimeClockObservation
    accounts: SqlContinuousAccount
    daily: SqlDailyRuntimeRisk
    previous: ResolvedContinuousAccount
    daily_snapshot: ResolvedDailyRuntimeSnapshot
    original_checked_at: datetime
    attempts: tuple[CanonicalDailyAttempt, ...]
    venue_account_id: str
    venue_model: VenueSourceReference


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RuntimeOperatingSnapshot:
    plan: RuntimeOperatingPlan
    clock: JournalReadSnapshot
    account: ContinuousIndexSnapshot
    daily_tables: tuple[RuntimeTableSnapshot, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedRuntimeOperatingEvidence:
    snapshot: RuntimeOperatingSnapshot
    clock: ResolvedJournalRead


@dataclass(frozen=True, slots=True)
class RuntimeOperatingSourceContext:
    """Original source values only; construction grants no ownership or authority.

    Fresh and historical readers authenticate the checkpoint, clock and complete
    attempt prefix before calling the shared evaluator with this value.
    """

    checkpoint: CausalEngineCheckpoint
    receipt: ContinuousAccountReceipt
    clock_reference: RuntimeClockReference
    clock: RuntimeClockObservation
    original_checked_at: datetime
    attempts: tuple[CanonicalDailyAttempt, ...]
    venue_account_id: str
    venue_model: VenueSourceReference


def _local_budget_reasons(
    *,
    attempts: tuple[CanonicalDailyAttempt, ...],
    checkpoint_rows: tuple[tuple[datetime, bool], ...],
    request_rows: tuple[tuple[datetime, bool], ...],
    evaluated_at: datetime,
    requested_count: int,
) -> list[str]:
    """Pure consistency calculation only; the concrete owner authenticates inputs."""
    reasons = []
    if not continuous_request_budget_available(
        request_rows,
        at=evaluated_at,
        count=requested_count,
        low_priority=True,
    ):
        reasons.append("LOCAL_MODELED_REQUEST_BUDGET_EXHAUSTED")
    first_sends = Counter(
        event.dispatch.record.dispatched_at
        for attempt in attempts
        for event in attempt.events
        if event.dispatch is not None
        and event.dispatch.record.dispatched_at > evaluated_at - timedelta(seconds=60)
    )
    low_rows = Counter(
        at for at, low in request_rows if low and at > evaluated_at - timedelta(seconds=60)
    )
    if first_sends != low_rows:
        reasons.append("LOCAL_FIRST_SEND_HISTORY_AND_ENGINE_ROWS_DIFFER")
    prior = Counter(row for row in checkpoint_rows if row[0] > evaluated_at - timedelta(seconds=60))
    if prior - Counter(request_rows):
        reasons.append("ORIGINAL_ENGINE_REQUEST_HISTORY_MISSING")
    return reasons


class SqlRuntimeOperatingEvidence:
    """Concrete mandatory source authenticator; constructors do not assert health.

    C authenticates the predecessor through its existing store. B authenticates
    complete attempts through its existing store. Their original bytes are
    captured/rechecked here, without recursively restoring either under SQL.
    """

    def __init__(
        self,
        engine: Engine,
        *,
        journal: SqlDurableJournal,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
        clock_sampler: RuntimeClockSampler,
    ) -> None:
        if type(journal) is not SqlDurableJournal:
            raise ValueError("operating evidence requires the same exact journal/engine")
        if type(clock_sampler) is not RuntimeClockSampler:
            raise ValueError("operating evidence requires the actual clock sampler")
        self.engine, self.journal, self.artifacts, self.codec = engine, journal, artifacts, codec
        self.clock_sampler = clock_sampler
        self._owned: WeakValueDictionary[int, Any] = WeakValueDictionary()
        self._original_fields: dict[int, tuple[object, ...]] = {}
        self._fingerprints: dict[int, str] = {}

    @staticmethod
    def _identities(value: Any) -> tuple[object, ...]:
        objects = [value]
        if isinstance(value, ResolvedRuntimeOperatingEvidence):
            objects.extend((value.snapshot, value.clock, value.clock.head))
            if value.clock.receipt is not None:
                objects.append(value.clock.receipt)
            value = value.snapshot
        if isinstance(value, RuntimeOperatingSnapshot):
            objects.extend((value.plan, value.clock, value.account, *value.daily_tables))
            for receipt in (value.clock.head_receipt, value.clock.requested_receipt):
                if receipt is not None:
                    objects.append(receipt)
            value = value.plan
        if isinstance(value, RuntimeOperatingPlan):
            objects.extend(
                (
                    value.clock,
                    value.clock.scope,
                    value.clock.policy,
                    value.clock_reference,
                    value.venue_model,
                    value.venue_model.producer,
                    value.venue_model.object_ref,
                    value.previous,
                    value.daily_snapshot,
                    value.daily_snapshot.raw,
                    value.daily_snapshot.raw.producer,
                    *value.daily_snapshot.raw.tables,
                    value.daily_snapshot.obligations,
                )
            )
            value = value.clock_reference
        elif isinstance(value, PreparedRuntimeClockAppend):
            objects.extend(
                (
                    value.append,
                    value.append.request,
                    *value.append.request.records,
                    *value.append.entries,
                    value.reference,
                )
            )
            value = value.reference
        if isinstance(value, RuntimeClockReference):
            objects.extend(
                (
                    value.key,
                    value.receipt,
                    value.record,
                    value.record.object_ref,
                    value.receipt.previous_head,
                    value.receipt.committed_head,
                )
            )
        return tuple(getattr(obj, f.name) for obj in objects for f in fields(obj))

    @staticmethod
    def _fingerprint(value: Any) -> str:
        if isinstance(value, ResolvedRuntimeOperatingEvidence):
            value = value.snapshot
        if isinstance(value, RuntimeOperatingSnapshot):
            value = value.plan
        if isinstance(value, RuntimeOperatingPlan):
            value.accounts.require_resolved(value.previous)
            value.daily.require_resolved_snapshot(value.daily_snapshot)
            return content_digest(
                (
                    value.clock_reference,
                    value.clock,
                    value.previous.checkpoint.semantic_sha256,
                    value.previous.request,
                    value.daily_snapshot.assignment_rows,
                    value.daily_snapshot.admissions,
                    value.daily_snapshot.obligations,
                    value.daily_snapshot.attempts,
                    value.daily_snapshot.attempt_envelopes,
                    value.attempts,
                    value.original_checked_at,
                    value.venue_account_id,
                    value.venue_model,
                )
            )
        if isinstance(value, PreparedRuntimeClockAppend):
            return value.reference.semantic_sha256
        raise ValueError("unsupported operating token")

    def _own(self, value: T) -> T:
        # Capture runs under SQL: inherit the already prepared fingerprint.
        # Full checkpoint/content validation is repeated only by detached users.
        if isinstance(value, RuntimeOperatingSnapshot):
            self._require(value.plan, RuntimeOperatingPlan)
            fingerprint = self._fingerprints[id(value.plan)]
        elif isinstance(value, ResolvedRuntimeOperatingEvidence):
            self._require(value.snapshot, RuntimeOperatingSnapshot)
            fingerprint = self._fingerprints[id(value.snapshot)]
        else:
            fingerprint = self._fingerprint(value)
        self._owned[id(value)] = value
        self._original_fields[id(value)] = self._identities(value)
        self._fingerprints[id(value)] = fingerprint
        finalize(value, self._original_fields.pop, id(value), None)
        finalize(value, self._fingerprints.pop, id(value), None)
        return value

    def _require(self, value: Any, expected: type[Any], *, deep: bool = False) -> None:
        if type(value) is not expected or self._owned.get(id(value)) is not value:
            raise ValueError("original operating-evidence token required")
        original, current = self._original_fields[id(value)], self._identities(value)
        if len(original) != len(current) or any(
            a is not b for a, b in zip(original, current, strict=True)
        ):
            raise ValueError("original operating token fields changed")
        if deep and self._fingerprints[id(value)] != self._fingerprint(value):
            raise ValueError("original operating token content changed")

    def clock_key(self) -> JournalKey:
        scope = self.clock_sampler.scope
        return JournalKey(
            namespace="coordinator",
            stream_id=canonical_id("runtime-clock", scope.stream_id),
            account_scope=scope.account_id,
            source_provider="local-runtime-clock/1",
            source_environment="synthetic",
            source_scope_sha256=content_digest(
                (scope, OPERATING_PROFILE, self.clock_sampler.profile)
            ),
        )

    def prepare_clock_append(
        self,
        sample: SampledRuntimeClock,
        *,
        expected_head: JournalHead,
    ) -> PreparedRuntimeClockAppend:
        self.clock_sampler.require_sample(sample)
        observed = sample.observation
        payload = self.codec.encode_record(observed)
        ref = ContinuousEvidenceRef(
            CLOCK_SCHEMA,
            self.artifacts.put(payload, max_bytes=256 * 1024),
            observed.semantic_sha256,
        )
        record = JournalRecord(observed.semantic_sha256, CLOCK_SCHEMA, payload)
        append = self.journal.prepare_append(
            self.clock_key(),
            JournalAppend(
                command_id=observed.semantic_sha256,
                command_sha256=observed.semantic_sha256,
                expected_head=expected_head,
                records=(record,),
            ),
        )
        return self._own(
            PreparedRuntimeClockAppend(
                RuntimeClockReference(key=self.clock_key(), receipt=append.receipt, record=ref),
                append,
            )
        )

    def append_clock_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedRuntimeClockAppend,
    ) -> RuntimeClockReference:
        self._require(prepared, PreparedRuntimeClockAppend)
        self.journal.append_in_transaction(connection, prepared.append)
        return prepared.reference

    def prepare(
        self,
        *,
        clock_reference: RuntimeClockReference,
        accounts: SqlContinuousAccount,
        daily: SqlDailyRuntimeRisk,
        previous: ResolvedContinuousAccount,
        daily_snapshot: ResolvedDailyRuntimeSnapshot,
        original_checked_at: datetime,
        venue_account_id: str,
        venue_model: VenueSourceReference,
    ) -> RuntimeOperatingPlan:
        require_utc(original_checked_at, "original operating check")
        require_identifier(venue_account_id, "independent venue account")
        if type(venue_model) is not VenueSourceReference:
            raise ValueError("exact independent venue model source required")
        if (
            type(accounts) is not SqlContinuousAccount
            or type(daily) is not SqlDailyRuntimeRisk
            or accounts.engine is not self.engine
            or daily.engine is not self.engine
        ):
            raise ValueError("operating context stores use a different database")
        accounts.require_resolved(previous)
        daily.require_resolved_snapshot(daily_snapshot)
        scope = previous.receipt.commit.scope
        if (
            scope != self.clock_sampler.scope
            or daily_snapshot.raw.account_id != scope.account_id
            or previous.checkpoint.now > original_checked_at
            or clock_reference.key != self.clock_key()
        ):
            raise ValueError("operating source scope or original context time differs")
        payload = self.artifacts.read(clock_reference.record.object_ref, max_bytes=256 * 1024)
        observed = self.codec.decode_record(payload, RuntimeClockObservation)
        if (
            type(observed) is not RuntimeClockObservation
            or observed.semantic_sha256 != clock_reference.record.semantic_sha256
            or self.codec.encode_record(observed) != payload
            or hashlib.sha256(payload).hexdigest()
            != clock_reference.record.object_ref.object_sha256
            or observed.scope != scope
            or observed.profile != self.clock_sampler.profile
        ):
            raise ValueError("retained clock observation binding differs")
        sequence = previous.receipt.commit.sequence
        admitted = {
            (envelope.event.attempt_id, envelope.event.sequence)
            for envelope in daily_snapshot.attempt_envelopes
            if envelope.coordinator_sequence <= sequence
        }
        attempts = tuple(
            reduce_daily_attempt(attempt.preparation, events)
            for attempt in daily_snapshot.attempts
            if (
                events := tuple(
                    event
                    for event in attempt.events
                    if (attempt.attempt_id, event.sequence) in admitted
                )
            )
        )
        if previous.receipt.commit.transition.resulting_heads.attempt_sha256 != (
            daily_attempt_inventory_sha256(attempts)
        ):
            raise ValueError("original account head differs from complete B attempt prefix")
        if any(
            attempt.preparation.request.source_account_id != scope.account_id
            or attempt.preparation.request.source_account_binding_sha256
            != scope.account_binding_sha256
            or attempt.preparation.request.venue_account_id != venue_account_id
            or attempt.preparation.request.venue_model != venue_model
            for attempt in attempts
        ):
            raise ValueError("local attempt source or independent venue scope differs")
        return self._own(
            RuntimeOperatingPlan(
                clock_reference,
                observed,
                accounts,
                daily,
                previous,
                daily_snapshot,
                original_checked_at,
                attempts,
                venue_account_id,
                venue_model,
            )
        )

    def capture_in_transaction(
        self,
        connection: Connection,
        plan: RuntimeOperatingPlan,
        *,
        budget: RuntimeReadBudget,
    ) -> RuntimeOperatingSnapshot:
        self._require(plan, RuntimeOperatingPlan)
        clock = self.journal.capture_in_transaction(
            connection,
            plan.clock_reference.key,
            command_id=plan.clock_reference.receipt.command_id,
        )
        account = plan.accounts.capture_commit_in_transaction(
            connection,
            scope=plan.previous.receipt.commit.scope,
            command_id=plan.previous.receipt.commit.transition.command_id,
        )
        if account is None or account.row != plan.previous.snapshot.row:
            raise ValueError("original operating checkpoint index changed")
        prior_account = next(
            (
                row
                for table in budget.captured
                if table.table is continuous_account_commits
                and table.account_id == account.scope.account_id
                for row in table.rows
                if row["command_id"] == account.row["command_id"]
            ),
            None,
        )
        if prior_account is not None and prior_account != account.row:
            raise ValueError("shared operating account capture changed")
        auxiliary = [] if prior_account is not None else [("account", account.row)]
        auxiliary.extend(
            (kind, row)
            for kind, row in (("stream", clock.stream), ("entry", clock.head_anchor))
            if row is not None
        )
        for receipt in (clock.head_receipt, clock.requested_receipt):
            if receipt is not None:
                auxiliary.append(("append", receipt.append))
                auxiliary.extend(("entry", row) for row in receipt.entries)
                if receipt.previous is not None:
                    auxiliary.append(("entry", receipt.previous))
        self._charge_auxiliary(budget, auxiliary)
        tables = tuple(
            next(
                (
                    item
                    for item in budget.captured
                    if item.table is old.table and item.account_id == old.account_id
                ),
                None,
            )
            or capture_runtime_table(
                connection, old.table, account_id=old.account_id, budget=budget
            )
            for old in plan.daily_snapshot.raw.tables
        )
        self._check_tables(plan, tables, require_current=False)
        return self._own(RuntimeOperatingSnapshot(plan, clock, account, tables))

    @staticmethod
    def _charge_auxiliary(
        budget: RuntimeReadBudget, rows: list[tuple[str, Mapping[str, Any]]]
    ) -> None:
        # These already transfer-bounded journal/index APIs have no account_id
        # projection compatible with capture_runtime_table. Charge their actual
        # detached copies as well; never exclude them from the shared ceiling.
        unique: dict[tuple[object, ...], Mapping[str, Any]] = {}
        for kind, row in rows:
            identity = (
                kind,
                row["account_id"] if kind == "account" else row["key_sha256"],
                row["sequence"] if kind == "entry" else row.get("command_id"),
            )
            if identity in unique and unique[identity] != row:
                raise ValueError("shared operating auxiliary row changed")
            unique[identity] = row
        payload = sum(
            len(value)
            for row in unique.values()
            for value in row.values()
            if isinstance(value, bytes)
        )
        metadata = sum(
            len(str(value).encode("utf-8"))
            for row in unique.values()
            for value in row.values()
            if value is not None and not isinstance(value, bytes)
        )
        budget.charge(len(unique), payload, metadata)

    def resolve(self, raw: RuntimeOperatingSnapshot) -> ResolvedRuntimeOperatingEvidence:
        self._require(raw, RuntimeOperatingSnapshot, deep=True)
        clock = self.journal.resolve_snapshot(raw.clock)
        if clock.receipt != raw.plan.clock_reference.receipt:
            raise ValueError("original clock journal receipt differs")
        # The receipt's exact record/payload is authenticated by the journal;
        # the independently retained object must have those same original bytes.
        record = raw.clock.requested_receipt
        if record is None:
            raise ValueError("clock sample was never journaled")
        # read_page is intentionally not called here: it would open a new SQL snapshot.
        payload_hash = raw.plan.clock_reference.record.object_ref.object_sha256
        if not any(row["payload_sha256"] == payload_hash for row in record.entries):
            raise ValueError("clock object and journal payload differ")
        return self._own(ResolvedRuntimeOperatingEvidence(raw, clock))

    def require_resolved(self, value: ResolvedRuntimeOperatingEvidence) -> None:
        self._require(value, ResolvedRuntimeOperatingEvidence, deep=True)

    @staticmethod
    def _check_tables(
        plan: RuntimeOperatingPlan,
        captured: tuple[RuntimeTableSnapshot, ...],
        *,
        require_current: bool,
    ) -> None:
        for before, after in zip(plan.daily_snapshot.raw.tables, captured, strict=True):
            if before.table is not after.table or before.account_id != after.account_id:
                raise ValueError("operating history table scope differs")
            if require_current:
                if before.rows != after.rows:
                    raise ValueError("current operating inventory changed")
            elif not before.table.name.endswith("heads"):
                columns = tuple(c.name for c in before.table.primary_key.columns)
                index = {tuple(row[c] for c in columns): row for row in after.rows}
                if any(index.get(tuple(row[c] for c in columns)) != row for row in before.rows):
                    raise ValueError("original operating history changed")

    def recheck_in_transaction(
        self,
        connection: Connection,
        value: ResolvedRuntimeOperatingEvidence,
        *,
        require_current: bool,
    ) -> None:
        self._require(value, ResolvedRuntimeOperatingEvidence)
        raw, plan = value.snapshot, value.snapshot.plan
        self.journal.recheck_in_transaction(
            connection, value.clock, require_current_head=require_current
        )
        original = plan.accounts.capture_commit_in_transaction(
            connection,
            scope=plan.previous.receipt.commit.scope,
            command_id=plan.previous.receipt.commit.transition.command_id,
        )
        if original != raw.account:
            raise ValueError("original operating account source changed")
        if (
            require_current
            and plan.accounts.capture_current_in_transaction(
                connection,
                scope=plan.previous.receipt.commit.scope,
            )
            != raw.account
        ):
            raise ValueError("current operating account head changed")
        tables = tuple(
            capture_runtime_table(
                connection,
                old.table,
                account_id=old.account_id,
                budget=budget,
            )
            for budget in (RuntimeReadBudget(),)
            for old in raw.daily_tables
        )
        self._check_tables(plan, tables, require_current=require_current)

    def require_current_clock(self, value: ResolvedRuntimeOperatingEvidence) -> None:
        """Separate concrete final clock guard; no journal refresh, SQL or delivery."""
        self._require(value, ResolvedRuntimeOperatingEvidence)
        self.clock_sampler.require_current(value.snapshot.plan.clock)

    def evaluate(
        self,
        value: ResolvedRuntimeOperatingEvidence,
        *,
        batch: DailyIntentBatch,
        phase: Literal["decision", "activation"],
        evaluated_at: datetime,
        request_rows: tuple[tuple[datetime, bool], ...],
    ) -> tuple[RuntimeOperatingFact, ...]:
        self.require_resolved(value)
        plan = value.snapshot.plan
        context = RuntimeOperatingSourceContext(
            plan.previous.checkpoint,
            plan.previous.receipt,
            plan.clock_reference,
            plan.clock,
            plan.original_checked_at,
            plan.attempts,
            plan.venue_account_id,
            plan.venue_model,
        )
        return evaluate_original_operating_facts(
            context, batch=batch, phase=phase, evaluated_at=evaluated_at, request_rows=request_rows
        )


def evaluate_original_operating_facts(
    plan: RuntimeOperatingSourceContext,
    *,
    batch: DailyIntentBatch,
    phase: Literal["decision", "activation"],
    evaluated_at: datetime,
    request_rows: tuple[tuple[datetime, bool], ...],
) -> tuple[RuntimeOperatingFact, ...]:
    """Evaluate already authenticated original sources without renewing their times.

    This pure calculation deliberately accepts source values, not an ownership
    token. Each caller must verify the actual original source journals first.
    """
    if phase not in ("decision", "activation") or evaluated_at != plan.original_checked_at:
        raise ValueError("operating evaluation cannot refresh original source time")
    cp, clock = plan.checkpoint, plan.clock
    if type(cp.inputs) is not ContinuousEngineInputs:
        raise ValueError("actual original continuous operating checkpoint required")
    scope = plan.receipt.commit.scope
    reference = ContinuousEvidenceRef(
        "continuous-checkpoint/1",
        plan.receipt.commit.transition.checkpoint,
        cp.semantic_sha256,
    )
    references = (plan.clock_reference.record, reference)
    source_id = content_digest(
        (
            OPERATING_PROFILE,
            references,
            plan.venue_account_id,
            plan.venue_model,
            daily_attempt_inventory_sha256(plan.attempts),
        )
    )
    instant = clock.observed_at_utc
    expiry = None if instant is None else instant + timedelta(seconds=30)
    if expiry is not None and clock.source_observed_at_utc is not None:
        expiry = min(expiry, clock.source_observed_at_utc + timedelta(seconds=30))
    mono_expiry = (
        None
        if (clock.observed_monotonic_ns is None or clock.source_observed_monotonic_ns is None)
        else min(clock.observed_monotonic_ns, clock.source_observed_monotonic_ns) + 30_000_000_000
    )
    clock_reasons = []
    if clock.profile != "explicit_simulation_time_model":
        clock_reasons.append("HOST_TIME_SOURCE_UNQUALIFIED")
    if clock.status != "healthy" or not clock.recovery_ready:
        clock_reasons.append("ORIGINAL_CLOCK_NOT_HEALTHY")
        clock_reasons.extend(
            _CLOCK_REASONS.get(reason, "STANDARD_CLOCK_UNKNOWN_REASON") for reason in clock.reasons
        )
    elif clock.reasons != ("within_limit",):
        clock_reasons.append("ORIGINAL_CLOCK_REASON_SET_INVALID")
    if instant is None or expiry is None or not instant <= evaluated_at < expiry:
        clock_reasons.append("ORIGINAL_CLOCK_MISSING_FUTURE_OR_EXPIRED")
    if clock.epoch is None or clock.observed_monotonic_ns is None:
        clock_reasons.append("ORIGINAL_CLOCK_EPOCH_UNAVAILABLE")
    calendar = cp.inputs.spec.calendar
    sessions = {s.session_label: s for s in calendar.sessions}
    labels = tuple(sessions)
    trigger = batch.target.trigger
    source, execution = trigger.source_session, trigger.execution_session
    session_reasons = []
    if (
        source not in sessions
        or execution not in sessions
        or labels.index(execution) != labels.index(source) + 1
        or batch.target.not_before != sessions[execution].opens_at + timedelta(minutes=5)
        or batch.target.expires_at != sessions[execution].opens_at + timedelta(minutes=10)
    ):
        session_reasons.append("PINNED_CALENDAR_OR_TARGET_WINDOW_DIFFERS")
    budget_reasons = _local_budget_reasons(
        attempts=plan.attempts,
        checkpoint_rows=cp.request_rows,
        request_rows=request_rows,
        evaluated_at=evaluated_at,
        requested_count=len(batch.intents),
    )
    rows = []
    for role, reasons, at, until, revision in (
        ("clock", clock_reasons, instant, expiry, clock.sequence),
        (
            "session",
            session_reasons,
            cp.now,
            batch.target.expires_at,
            plan.receipt.commit.sequence,
        ),
        (
            "request_budget",
            budget_reasons,
            cp.now,
            batch.target.expires_at,
            plan.receipt.commit.sequence,
        ),
    ):
        rows.append(
            RuntimeOperatingFact(
                role=cast(Any, role),
                scope=scope,
                profile=OPERATING_PROFILE,
                source_sha256=source_id,
                source_at=at,
                received_at=at,
                valid_until=until,
                revision=revision,
                references=references,
                clock_epoch=clock.epoch,
                clock_valid_until_monotonic_ns=mono_expiry,
                status="available" if not reasons else "unavailable",
                reasons=tuple(sorted(set(reasons))),
                clock_profile=clock.profile,
                calendar_class=cast(Any, str(cp.inputs.spec.data_class)),
            )
        )
    return tuple(rows)
