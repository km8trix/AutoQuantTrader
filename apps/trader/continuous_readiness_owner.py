"""One bounded in-process owner of original synthetic readiness checks.

The private composition context owns setup and teardown on the owner thread.
This module neither loads a configured account nor acquires/renews a lease, and
its ephemeral responses grant no operational or authentication authority.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import timedelta
from threading import Condition, Event, Lock, Thread, current_thread
from typing import Literal
from uuid import uuid4

from sqlalchemy import Engine

from apps.trader.readiness_store_binding import (
    ReadinessStoreBinding,
    _StoreBindingValues,
    _StoreIdentityValues,
    _validated_store_identity,
)
from apps.trader.synthetic_session_genesis import _database_path, _require_input_profile
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.personal_runtime import LocalInstanceGuard
from packages.application.stateful_venue import initialize_stateful_venue
from packages.domain.account_coordinator import AccountFenceReceipt, AccountLease
from packages.domain.continuous_engine_contracts import ContinuousEngineInputs
from packages.domain.durable_journal_contracts import empty_head
from packages.domain.identifiers import canonical_id
from packages.domain.operational_control import OperationalControlState
from packages.domain.personal_contracts import content_digest
from packages.domain.research_job_contracts import require_identifier
from packages.persistence.continuous_integrity import SqlContinuousIntegrityReader
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.continuous_simulation_delivery import SqlContinuousSimulationDelivery
from packages.persistence.database import _repeatable_read_transaction, verify_operational_schema
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.stateful_venue import SqlStatefulVenue, venue_journal_key

_MAX_NS = 2**63 - 1
_POLL_SECONDS = 0.02
_EVENT_IS_SET = Event.is_set
_EVENT_SET = Event.set
type _Phase = Literal["new", "starting", "idle", "busy", "stopping", "stopped"]


def _event_is_set(event: Event) -> bool:
    observed = _EVENT_IS_SET(event)
    if type(observed) is not bool:
        raise ValueError("READINESS_EVENT_STATE_INVALID")
    return observed


@dataclass(frozen=True, slots=True, kw_only=True)
class ReadinessOwnerLimits:
    startup_ns: int = 10_000_000_000
    request_ns: int = 5_000_000_000
    shutdown_ns: int = 1_000_000_000
    lifetime_ns: int = 60_000_000_000

    def __post_init__(self) -> None:
        for value, maximum in (
            (self.startup_ns, 10_000_000_000),
            (self.request_ns, 5_000_000_000),
            (self.shutdown_ns, 1_000_000_000),
            (self.lifetime_ns, 60_000_000_000),
        ):
            if type(value) is not int or not 0 < value <= maximum:
                raise ValueError("READINESS_LIMIT_INVALID")
        if self.shutdown_ns >= self.lifetime_ns:
            raise ValueError("READINESS_SHUTDOWN_RESERVE_REQUIRED")


_DEFAULT_LIMITS = ReadinessOwnerLimits()


@dataclass(frozen=True, slots=True)
class ReadinessOwnerStatus:
    phase: _Phase
    busy: bool
    cleanup_complete: bool
    primary_failure: str | None
    cleanup_failure: str | None
    incarnation: str


@dataclass(frozen=True, slots=True)
class ReadinessCheckResult:
    status: Literal["ready", "unavailable"]
    reason: str
    request_id: str
    incarnation: str


class _DeadlineExpired(ValueError):
    pass


class _ClockInvalid(ValueError):
    pass


class _ReadinessRuntime:
    """Exact thread-owned graph; the surrounding context owns its cleanup."""

    def __init__(
        self,
        *,
        reader: SqlContinuousIntegrityReader,
        lease: AccountLease,
        guard: LocalInstanceGuard,
        venue: SqlStatefulVenue,
        venue_engine: Engine,
        stop_event: Event,
    ) -> None:
        if (
            type(reader) is not SqlContinuousIntegrityReader
            or type(lease) is not AccountLease
            or type(guard) is not LocalInstanceGuard
            or type(venue) is not SqlStatefulVenue
            or type(venue_engine) is not Engine
            or type(stop_event) is not Event
            or type(reader.engine) is not Engine
            or venue_engine is reader.engine
            or reader.account.codec is not personal_codec
            or reader.fence != lease.fence
        ):
            raise ValueError("READINESS_ORIGINAL_RUNTIME_REQUIRED")
        runtime = reader.daily.producers
        if (
            type(runtime) is not SqlContinuousRuntimeSources
            or type(venue.journal) is not SqlDurableJournal
            or venue.journal._engine is not venue_engine
            or venue.model is not runtime.venue_model
            or venue.accounting is None
            or venue.accounting is not runtime.accounting
            or venue.codec is not personal_codec
            or venue.journal._codec is not personal_codec
            or venue.key != venue_journal_key(venue.model)
            or type(venue.artifacts) is not LocalResearchArtifactStore
            or type(runtime.artifacts) is not LocalResearchArtifactStore
            or (
                venue.verified_sources is not None
                and type(venue.verified_sources) is not SqlContinuousSimulationDelivery
            )
        ):
            raise ValueError("READINESS_ORIGINAL_VENUE_REQUIRED")
        if _database_path(reader.engine).samefile(_database_path(venue_engine)):
            raise ValueError("READINESS_INDEPENDENT_STORES_REQUIRED")
        if venue.artifacts._root.samefile(runtime.artifacts._root):
            raise ValueError("READINESS_INDEPENDENT_STORES_REQUIRED")
        lease.__post_init__()
        policy = reader.account.coordinator._authority.policy
        if (
            policy.lease_ttl != timedelta(seconds=60)
            or policy.maximum_in_flight_duration != timedelta(seconds=5)
            or policy.takeover_safety_interval != timedelta(seconds=10)
            or policy.semantic_sha256 != lease.policy_sha256
            or lease.revision_number != 1
        ):
            raise ValueError("READINESS_ORIGINAL_LEASE_POLICY_REQUIRED")
        self.reader, self.lease, self.guard = reader, lease, guard
        self.venue = venue
        self.venue_engine, self.stop_event = venue_engine, stop_event
        self._instance, self._thread = self, current_thread()
        self._bindings = self._binding_values()
        self._lease_sha = lease.semantic_sha256
        self._scope_sha = reader.scope.semantic_sha256
        self._venue_model_sha = venue.model.semantic_sha256
        self._venue_key_sha = venue.key.semantic_sha256
        # Reuse the original pure reducer; never initialize or repair storage.
        self._venue_initial = initialize_stateful_venue(venue.model, accounting=venue.accounting)
        self._descriptor = guard.fileno()
        self._last_ns: int | None = None
        self._lease_deadline_ns = _MAX_NS
        self._lease_deadline()
        self._original = self._supported_state()
        self._lease_deadline()
        self._store_identity_values: _StoreIdentityValues | None = None

    def _bind_store_identity(self, values: object) -> None:
        """Retain one native projection after actual owner-thread store admission."""
        self._require()
        if self._store_identity_values is not None:
            raise ValueError("READINESS_STORE_IDENTITY_ALREADY_BOUND")
        identity = _validated_store_identity(values)
        # The configured factory is already loaded for this optional producer;
        # keep its existing private-path predicates off ordinary Runtime imports.
        from apps.trader.continuous_simulation_factory import _existing_private

        actual_path = _database_path(self.reader.engine)
        path = _existing_private(str(actual_path), directory=False)
        before = path.lstat()
        scope = self.reader.scope
        if identity[:6] != (
            scope.account_id,
            scope.account_binding_sha256,
            scope.stream_id,
            str(path),
            before.st_dev,
            before.st_ino,
        ):
            raise ValueError("READINESS_STORE_IDENTITY_DIFFERS")
        self._require()
        after_path = _existing_private(str(_database_path(self.reader.engine)), directory=False)
        after = after_path.lstat()
        if (str(after_path), after.st_dev, after.st_ino) != identity[3:6]:
            raise ValueError("READINESS_STORE_IDENTITY_DIFFERS")
        self._require()
        # The final digest is G's encoded-payload provenance. This method binds
        # native shape and actual store/scope only; it never reattests that hash.
        self._store_identity_values = identity

    @property
    def lease_deadline_ns(self) -> int:
        """Private host ceiling, not a transferable receipt or authority."""
        self._require()
        return self._lease_deadline_ns

    def _binding_values(self) -> tuple[object, ...]:
        runtime = self._runtime_sources()
        venue_artifacts, account_artifacts = self.venue.artifacts, runtime.artifacts
        if (
            type(venue_artifacts) is not LocalResearchArtifactStore
            or type(account_artifacts) is not LocalResearchArtifactStore
        ):
            raise ValueError("READINESS_ORIGINAL_RUNTIME_CHANGED")
        return (
            self.reader,
            self.lease,
            self.guard,
            self.venue_engine,
            self.stop_event,
            self.reader.engine,
            self.reader.account,
            self.reader.account.coordinator,
            self.reader.daily,
            self.reader.publisher,
            self.reader.associations,
            self.reader.scope,
            self.reader.fence,
            self.venue,
            self.venue.model,
            self.venue.key,
            self.venue.journal,
            self.venue.journal._engine,
            self.venue.journal._codec,
            self.venue.journal._types,
            venue_artifacts,
            venue_artifacts._root,
            self.venue.accounting,
            self.venue.codec,
            self.venue.verified_sources,
            runtime.venue_model,
            runtime.venue_reference,
            runtime.accounting,
            account_artifacts,
            account_artifacts._root,
        )

    def _runtime_sources(self) -> SqlContinuousRuntimeSources:
        runtime = self.reader.daily.producers
        if type(runtime) is not SqlContinuousRuntimeSources:
            raise ValueError("READINESS_ORIGINAL_RUNTIME_CHANGED")
        return runtime

    def _require(self) -> None:
        runtime = self._runtime_sources()
        if (
            type(self) is not _ReadinessRuntime
            or self._instance is not self
            or current_thread() is not self._thread
            or any(a is not b for a, b in zip(self._binding_values(), self._bindings, strict=True))
            or self.lease.semantic_sha256 != self._lease_sha
            or self.reader.scope.semantic_sha256 != self._scope_sha
            or self.venue.model.semantic_sha256 != self._venue_model_sha
            or self.venue.key.semantic_sha256 != self._venue_key_sha
            or runtime.venue_reference.semantic_sha256_ref != self._venue_model_sha
            or self.guard.fileno() != self._descriptor
            or self.reader.fence != self.lease.fence
        ):
            raise ValueError("READINESS_ORIGINAL_RUNTIME_CHANGED")
        self.reader._require_graph()
        if _event_is_set(self.stop_event):
            raise ValueError("READINESS_OWNER_STOPPED")
        delivery = self.venue.verified_sources
        if delivery is not None and (
            type(delivery) is not SqlContinuousSimulationDelivery
            or delivery.runtime is not runtime
            or delivery.accounts is not self.reader.account
            or delivery.daily is not self.reader.daily
            or delivery._require_owners() is not self.venue
        ):
            raise ValueError("READINESS_ORIGINAL_RUNTIME_CHANGED")

    def _venue_state(self) -> tuple[str, str, str]:
        self._require()
        venue = self.venue
        # No historical through_head: each bookend observes the actual head.
        retained = venue.read()
        self._require()
        receipt = venue.journal.read_receipt(
            venue.key, canonical_id("venue-genesis/1", self._venue_model_sha)
        )
        self._require()
        if (
            retained.head.sequence != 1
            or retained.state != self._venue_initial
            or receipt is None
            or receipt.command_sha256 != self._venue_model_sha
            or receipt.previous_head != empty_head(venue.key)
            or receipt.committed_head != retained.head
            or venue.journal.read_head(venue.key) != retained.head
        ):
            raise ValueError("READINESS_INITIAL_VENUE_REQUIRED")
        self._require()
        return (
            retained.head.semantic_sha256,
            retained.state.semantic_sha256,
            receipt.semantic_sha256,
        )

    def _now(self) -> int:
        try:
            now = time.monotonic_ns()
        except BaseException:
            raise _ClockInvalid("READINESS_CLOCK_INVALID") from None
        if (
            type(now) is not int
            or not 0 <= now <= _MAX_NS
            or (self._last_ns is not None and now < self._last_ns)
        ):
            raise _ClockInvalid("READINESS_CLOCK_INVALID")
        self._last_ns = now
        return now

    def _lease_deadline(self) -> int:
        self._require()
        before = self._now()
        receipt = self.reader.account.coordinator.revalidate(self.lease.fence)
        self._require()
        if type(receipt) is not AccountFenceReceipt or (
            receipt.fence,
            receipt.lease_sha256,
            receipt.policy_sha256,
            receipt.valid_until,
        ) != (
            self.lease.fence,
            self._lease_sha,
            self.lease.policy_sha256,
            self.lease.expires_at,
        ):
            raise ValueError("READINESS_ORIGINAL_LEASE_REVISION_REQUIRED")
        remaining = receipt.valid_until - receipt.validated_at
        remaining_ns = (
            (remaining.days * 86_400 + remaining.seconds) * 1_000_000 + remaining.microseconds
        ) * 1_000
        if not 0 < remaining_ns <= 60_000_000_000:
            raise ValueError("READINESS_LEASE_VALIDITY_INVALID")
        self._lease_deadline_ns = min(self._lease_deadline_ns, before + remaining_ns, _MAX_NS)
        if self._now() >= self._lease_deadline_ns:
            raise ValueError("READINESS_LEASE_EXPIRED")
        return self._lease_deadline_ns

    def _supported_state(self) -> tuple[str, str, str, str | None, tuple[str, str, str]]:
        self._require()
        reader = self.reader
        actual = reader.account.restore(reader.scope)
        if actual is None:
            raise ValueError("READINESS_NONEMPTY_ACCOUNT_REQUIRED")
        reader.account.require_resolved(actual)
        inputs = actual.checkpoint.inputs
        if type(inputs) is not ContinuousEngineInputs:
            raise ValueError("READINESS_CONTINUOUS_INPUTS_REQUIRED")
        _require_input_profile(inputs)
        spec, state = inputs.spec, actual.checkpoint.state
        runtime = reader.daily.producers
        if type(runtime) is not SqlContinuousRuntimeSources:
            raise ValueError("READINESS_ORIGINAL_RUNTIME_SOURCES_REQUIRED")
        if (
            actual.receipt.commit.sequence != 1
            or actual.receipt.commit.scope != reader.scope
            or actual.request != inputs
            or spec.account_id != reader.scope.account_id
            or spec.account_binding_sha256 != reader.scope.account_binding_sha256
            or spec.deployment_id != reader.scope.stream_id
            or len(state.cash_flows) != 1
            or state.cash_flows[0] != runtime.venue_model.initial_cash_flow
            or state.cash_flows[0].amount != spec.initial_cash
            or state.submissions
            or state.broker_events
            or state.commitments
            or actual.checkpoint.runtime_decisions
            or runtime.forward_sources.evidence_class != "synthetic_fixture"
            or runtime.operating.clock_sampler.profile != "explicit_simulation_time_model"
            or runtime.venue_model.live_authorized is not False
            or runtime.venue_model.source_mode != "synthetic_fixture"
        ):
            raise ValueError("READINESS_DEFAULT_SYNTHETIC_C1_REQUIRED")
        current = reader.daily.resolve_snapshot(
            reader.daily.read_snapshot(account_id=reader.scope.account_id, fence=self.lease.fence)
        )
        reader.daily.require_resolved_snapshot(current)
        if (
            current.control is None
            or current.control.effective_state is not OperationalControlState.HALTED
            or current.control.active_operation is not None
            or current.admissions
            or current.obligations.bindings
            or current.attempts
            or current.attempt_envelopes
            or current.observed_groups
        ):
            raise ValueError("READINESS_HALTED_INITIAL_INVENTORY_REQUIRED")
        assignment = current.assignment
        association = None
        if assignment is None:
            if current.assignment_rows:
                raise ValueError("READINESS_EMPTY_ASSIGNMENT_REQUIRED")
        else:
            if (
                current.assignment_rows != (assignment,)
                or assignment.account_id != reader.scope.account_id
                or assignment.account_binding_sha256 != reader.scope.account_binding_sha256
                or assignment.generation != 1
                or assignment.previous_assignment_sha256 is not None
                or assignment.enabled_for_new_exposure is not False
                or assignment.live_authorized is not False
                or assignment.policy != spec.risk_policy
                or assignment.strategy != spec.strategy
                or assignment.configuration_sha256 != content_digest(spec.strategy_configuration)
                or assignment.instrument_symbols != spec.instruments
                or assignment.producer_map_sha256 != runtime.producer_map.semantic_sha256
            ):
                raise ValueError("READINESS_DISABLED_INITIAL_SELECTION_REQUIRED")
            association = reader.associations.read(
                reader.scope, current=current, assignment_generation=1
            )
            reader.associations.require_association(association)
            if (
                association.dependencies.previous != actual.receipt
                or association.dependencies.proposed != assignment
                or association.dependencies.previous_assignment_sha256 is not None
                or association.canonical.receipt != actual.receipt
                or association.checkpoint != actual.checkpoint
                or association.prefix.before_assignment is not None
                or association.prefix.after_assignment != assignment
                or association.reconciliation is not None
            ):
                raise ValueError("READINESS_ORIGINAL_SELECTION_HISTORY_REQUIRED")
        with _repeatable_read_transaction(reader.engine) as connection:
            if association is not None:
                reader.associations.recheck_in_transaction(connection, association)
            reader.account.recheck_in_transaction(connection, actual, require_current=True)
            reader.daily.recheck_snapshot_in_transaction(
                connection, current, fence=self.lease.fence
            )
        reader.account.require_resolved(actual)
        reader.daily.require_resolved_snapshot(current)
        self._require()
        venue = self._venue_state()
        if self.venue.model.initial_cash_flow != state.cash_flows[0]:
            raise ValueError("READINESS_DEFAULT_SYNTHETIC_C1_REQUIRED")
        return (
            actual.receipt.semantic_sha256,
            actual.checkpoint.semantic_sha256,
            current.control.semantic_sha256,
            None if assignment is None else assignment.semantic_sha256,
            venue,
        )

    def _before(self, deadline_ns: int) -> None:
        self._require()
        now = self._now()
        if now >= self._lease_deadline_ns:
            raise ValueError("READINESS_LEASE_EXPIRED")
        if now >= deadline_ns:
            raise _DeadlineExpired("READINESS_DEADLINE_EXPIRED")

    def verify(self, deadline_ns: int) -> int:
        if type(deadline_ns) is not int or not 0 < deadline_ns <= _MAX_NS:
            raise ValueError("READINESS_DEADLINE_INVALID")
        self._before(deadline_ns)
        with self.reader.account.cooperative_stop_scope(self.stop_event):
            deadline_ns = min(deadline_ns, self._lease_deadline())
            if self._supported_state() != self._original:
                raise ValueError("READINESS_INITIAL_STATE_CHANGED")
            self._before(deadline_ns)
            verify_operational_schema(
                self.reader.engine,
                research_codec=personal_codec,
                continuous_integrity=self.reader,
            )
            self._before(deadline_ns)
            if self._supported_state() != self._original:
                raise ValueError("READINESS_INITIAL_STATE_CHANGED")
            deadline_ns = min(deadline_ns, self._lease_deadline())
            self._before(deadline_ns)
        self._before(deadline_ns)
        return deadline_ns


@dataclass(slots=True)
class _Request:
    # This distinct object is the private nonce; textual IDs never select results.
    request_id: str
    deadline_ns: int
    cancel_event: Event | None
    abandoned: bool = False
    result: ReadinessCheckResult | None = None


class ContinuousReadinessOwner:
    """A single private runtime, one request slot, and no implicit restart."""

    def __init__(
        self,
        *,
        _open_runtime: Callable[[Event], AbstractContextManager[_ReadinessRuntime]],
        limits: ReadinessOwnerLimits = _DEFAULT_LIMITS,
    ) -> None:
        if type(limits) is not ReadinessOwnerLimits or not callable(_open_runtime):
            raise ValueError("READINESS_OWNER_CONFIGURATION_INVALID")
        limits.__post_init__()
        self._limits = ReadinessOwnerLimits(
            startup_ns=limits.startup_ns,
            request_ns=limits.request_ns,
            shutdown_ns=limits.shutdown_ns,
            lifetime_ns=limits.lifetime_ns,
        )
        self._open_runtime = _open_runtime
        self._condition = Condition(Lock())
        self._stop_event = Event()
        self._stop_latched = False
        self._thread: Thread | None = None
        self._phase: _Phase = "new"
        self._busy = False
        self._finalized = False
        self._cleanup_ok = True
        self._primary_failure: str | None = None
        self._cleanup_failure: str | None = None
        self._incarnation = uuid4().hex
        self._slot: _Request | None = None
        self._last_ns: int | None = None
        self._startup_deadline = _MAX_NS
        self._lifetime_deadline = _MAX_NS
        self._work_deadline = _MAX_NS
        self._store_binding_values: _StoreBindingValues | None = None

    def store_binding(self) -> ReadinessStoreBinding | None:
        """Return fresh audit data without I/O, clock sampling or readiness work."""
        with self._condition:
            values = self._store_binding_values
            if values is None:
                return None
            if type(values) is not tuple or len(values) != 8:
                raise ValueError("READINESS_STORE_BINDING_INVALID")
            return ReadinessStoreBinding(*values)

    def _latch(self, reason: str | None) -> None:
        if reason is not None and self._primary_failure is None:
            self._primary_failure = reason
        _EVENT_SET(self._stop_event)
        self._stop_latched = True
        self._phase = "stopping"
        if self._thread is None:
            self._finalized, self._cleanup_ok = True, True
        self._condition.notify_all()

    def _now(self) -> int | None:
        # Every call is under this Condition: sample and memo update cannot be
        # reordered by a concurrent caller and mistaken for clock regression.
        try:
            now = time.monotonic_ns()
        except BaseException:
            self._latch("clock_invalid")
            return None
        if (
            type(now) is not int
            or not 0 <= now <= _MAX_NS
            or (self._last_ns is not None and now < self._last_ns)
        ):
            self._latch("clock_invalid")
            return None
        self._last_ns = now
        if self._phase not in ("new", "stopped"):
            try:
                stopped = _event_is_set(self._stop_event)
            except BaseException:
                self._latch("stop_invalid")
                return None
            if self._stop_latched or stopped:
                self._latch(None)
        if self._phase not in ("new", "stopping", "stopped") and now >= self._work_deadline:
            self._latch("lifetime_expired")
        return now

    def _snapshot(self) -> ReadinessOwnerStatus:
        alive = self._thread is not None and self._thread.is_alive()
        if self._finalized and not alive:
            self._phase = "stopped"
        complete = self._phase == "new" or (self._finalized and not alive and self._cleanup_ok)
        return ReadinessOwnerStatus(
            self._phase,
            self._busy,
            complete,
            self._primary_failure,
            self._cleanup_failure,
            self._incarnation,
        )

    def status(self) -> ReadinessOwnerStatus:
        with self._condition:
            return self._snapshot()

    def _unavailable(self, request_id: str, reason: str) -> ReadinessCheckResult:
        return ReadinessCheckResult("unavailable", reason, request_id, self._incarnation)

    def start(self) -> ReadinessOwnerStatus:
        with self._condition:
            if self._phase != "new":
                return self._snapshot()
            now = self._now()
            if now is None or now > _MAX_NS - self._limits.lifetime_ns:
                self._latch("clock_invalid")
                self._finalized = True
                return self._snapshot()
            self._lifetime_deadline = now + self._limits.lifetime_ns
            self._work_deadline = self._lifetime_deadline - self._limits.shutdown_ns
            self._startup_deadline = min(now + self._limits.startup_ns, self._work_deadline)
            self._phase, self._busy, self._cleanup_ok = "starting", True, False
            self._thread = Thread(target=self._run, name="continuous-readiness-owner", daemon=False)
            try:
                self._thread.start()
            except BaseException:
                # Even an ordinary exception may follow native launch but
                # precede Thread.start's acknowledgement. Only _run can prove
                # its eventual exit; is_alive() alone cannot prove no launch.
                self._latch("startup_failed")
                return self._snapshot()
            while self._phase == "starting":
                now = self._now()
                if now is None:
                    break
                if now >= self._startup_deadline:
                    self._latch("startup_deadline")
                    break
                self._condition.wait(min(_POLL_SECONDS, (self._startup_deadline - now) / 1e9))
            return self._snapshot()

    def check(self, request_id: str, *, cancel_event: Event | None = None) -> ReadinessCheckResult:
        require_identifier(request_id, "readiness request")
        if cancel_event is not None and type(cancel_event) is not Event:
            raise ValueError("READINESS_CANCEL_EVENT_INVALID")
        with self._condition:
            if current_thread() is self._thread:
                return self._unavailable(request_id, "reentrant")
            now = self._now()
            if now is None:
                return self._unavailable(request_id, "clock_invalid")
            if self._phase != "idle":
                reason = "not_started" if self._phase == "new" else self._phase
                return self._unavailable(request_id, reason)
            if self._slot is not None or self._busy:
                return self._unavailable(request_id, "busy")
            if cancel_event is not None and _event_is_set(cancel_event):
                return self._unavailable(request_id, "cancelled")
            deadline = min(now + self._limits.request_ns, self._work_deadline)
            request = _Request(request_id, deadline, cancel_event)
            self._slot, self._busy, self._phase = request, True, "busy"
            self._condition.notify_all()
            try:
                while True:
                    now = self._now()
                    if now is None:
                        request.abandoned = True
                        return self._unavailable(request_id, "clock_invalid")
                    if cancel_event is not None and _event_is_set(cancel_event):
                        request.abandoned = True
                        self._condition.notify_all()
                        return self._unavailable(request_id, "cancelled")
                    if now >= request.deadline_ns:
                        request.abandoned = True
                        self._condition.notify_all()
                        return self._unavailable(request_id, "deadline")
                    if request.result is not None:
                        if request.result.status == "ready" and self._stop_latched:
                            return self._unavailable(request_id, "stopping")
                        return request.result
                    if self._stop_latched:
                        request.abandoned = True
                        return self._unavailable(request_id, "stopping")
                    self._condition.wait(min(_POLL_SECONDS, (request.deadline_ns - now) / 1e9))
            except BaseException:
                request.abandoned = True
                self._condition.notify_all()
                raise

    def stop(self) -> ReadinessOwnerStatus:
        with self._condition:
            if self._phase == "new":
                self._latch(None)
                self._finalized = True
                return self._snapshot()
            if self._snapshot().phase == "stopped":
                return self._snapshot()
            self._latch(None)
            if current_thread() is self._thread:
                return self._snapshot()
            now = self._now()
            if now is None:
                return self._snapshot()
            deadline = min(now + self._limits.shutdown_ns, _MAX_NS)
            while not (
                self._finalized and self._thread is not None and not self._thread.is_alive()
            ):
                now = self._now()
                if now is None or now >= deadline:
                    break
                self._condition.wait(min(_POLL_SECONDS, (deadline - now) / 1e9))
            result = self._snapshot()
        if result.phase == "stopped" and self._thread is not None:
            self._thread.join(timeout=0)
        return result

    def _serve(self, runtime: _ReadinessRuntime) -> None:
        while True:
            with self._condition:
                now = self._now()
                # This snapshot is valid only while this lock is held. Work
                # below releases it, and another caller can latch stop then.
                stopped = self._stop_latched
                if now is None or stopped:
                    return
                request = self._slot
                if request is None:
                    self._condition.wait(min(_POLL_SECONDS, (self._work_deadline - now) / 1e9))
                    continue
                if (
                    request.abandoned
                    or (request.cancel_event is not None and _event_is_set(request.cancel_event))
                    or now >= request.deadline_ns
                ):
                    request.result = self._unavailable(request.request_id, "deadline")
                    self._slot, self._busy, self._phase = None, False, "idle"
                    self._condition.notify_all()
                    continue
            failure: BaseException | None = None
            reason = "verified"
            deadline = request.deadline_ns
            ceiling = request.deadline_ns
            try:
                returned = runtime.verify(deadline)
                if type(returned) is not int or not 0 < returned <= request.deadline_ns:
                    raise ValueError("READINESS_RESULT_DEADLINE_INVALID")
                deadline = returned
                ceiling = runtime.lease_deadline_ns
                if type(ceiling) is not int or not 0 < ceiling <= _MAX_NS:
                    raise ValueError("READINESS_LEASE_DEADLINE_INVALID")
                deadline = min(deadline, ceiling)
            except _DeadlineExpired:
                reason = "deadline"
            except BaseException as error:
                failure = error
                reason = "clock_invalid" if isinstance(error, _ClockInvalid) else "runtime_failed"
            with self._condition:
                now = self._now()
                request.deadline_ns = min(request.deadline_ns, deadline)
                if failure is None and reason == "verified":
                    self._work_deadline = min(self._work_deadline, ceiling)
                if failure is not None:
                    self._latch(reason)
                elif now is None:
                    reason = "clock_invalid"
                elif self._stop_latched:
                    reason = "stopping"
                elif now >= request.deadline_ns:
                    reason = "deadline"
                elif request.abandoned or (
                    request.cancel_event is not None and _event_is_set(request.cancel_event)
                ):
                    reason = "cancelled"
                request.result = (
                    ReadinessCheckResult("ready", "verified", request.request_id, self._incarnation)
                    if reason == "verified"
                    else self._unavailable(request.request_id, reason)
                )
                self._slot, self._busy = None, False
                if not self._stop_latched:
                    self._phase = "idle"
                self._condition.notify_all()
            if failure is not None:
                raise failure

    def _run(self) -> None:
        context: AbstractContextManager[_ReadinessRuntime] | None = None
        entered = False
        primary: BaseException | None = None
        partial_cleanup_failed = False
        try:
            with self._condition:
                if self._stop_latched:
                    return
            context = self._open_runtime(self._stop_event)
            runtime = context.__enter__()
            entered = True
            if type(runtime) is not _ReadinessRuntime or runtime.stop_event is not self._stop_event:
                raise ValueError("READINESS_ORIGINAL_RUNTIME_REQUIRED")
            ceiling = runtime.lease_deadline_ns
            if type(ceiling) is not int or not 0 < ceiling <= _MAX_NS:
                raise ValueError("READINESS_LEASE_DEADLINE_INVALID")
            raw_identity = getattr(runtime, "_store_identity_values", None)
            identity: _StoreIdentityValues | None = (
                None if raw_identity is None else _validated_store_identity(raw_identity)
            )
            with self._condition:
                self._work_deadline = min(self._work_deadline, ceiling)
                now = self._now()
                if now is not None and now >= self._startup_deadline:
                    self._latch("startup_deadline")
                if now is None or self._stop_latched:
                    return
                if identity is not None:
                    self._store_binding_values = (self._incarnation, *identity)
                self._phase, self._busy = "idle", False
                self._condition.notify_all()
            self._serve(runtime)
        except BaseException as error:
            primary = error
            # The trusted setup context preserves a primary plus failed partial
            # cleanup as an ordered group. No __exit__ exists after failed enter.
            partial_cleanup_failed = not entered and isinstance(error, BaseExceptionGroup)
            with self._condition:
                if self._primary_failure is None:
                    self._latch("startup_failed" if self._phase == "starting" else "runtime_failed")
        finally:
            cleanup_ok = not partial_cleanup_failed
            if entered and context is not None:
                try:
                    if primary is None:
                        context.__exit__(None, None, None)
                    else:
                        context.__exit__(type(primary), primary, primary.__traceback__)
                except BaseException:
                    cleanup_ok = False
            with self._condition:
                if not cleanup_ok:
                    self._cleanup_failure = "cleanup_failed"
                self._cleanup_ok = cleanup_ok
                self._busy, self._finalized, self._phase = False, True, "stopping"
                self._stop_latched = True
                _EVENT_SET(self._stop_event)
                self._condition.notify_all()
