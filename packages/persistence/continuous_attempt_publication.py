"""Atomic C/B attempt publication; a receipt does not authorize venue delivery."""

from dataclasses import dataclass, fields
from threading import Lock
from weakref import WeakValueDictionary, finalize

from packages.domain.account_coordinator import AccountFence
from packages.domain.continuous_persistence_contracts import ContinuousAccountReceipt
from packages.domain.submission_attempt import SubmissionAttemptState
from packages.persistence.continuous_account import PreparedContinuousCommit, SqlContinuousAccount
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_runtime_attempt_sources import (
    PreparedContinuousRuntimeAttemptSource,
    SqlContinuousRuntimeAttemptSources,
)
from packages.persistence.daily_runtime_risk import PreparedDailyAttemptMutation


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CommittedSimulationAttemptBatch:
    """Original successful COMMIT ownership; fresh one-use delivery checks remain required."""

    receipt: ContinuousAccountReceipt
    account: PreparedContinuousCommit
    attempts: PreparedDailyAttemptMutation


class SqlContinuousAttemptPublication:
    def __init__(self, *, account: SqlContinuousAccount) -> None:
        if (
            type(account) is not SqlContinuousAccount
            or type(account.composer) is not SqlContinuousCommitComposer
        ):
            raise ValueError("EXACT_ATTEMPT_PUBLICATION_OWNERS_REQUIRED")
        self.account, self.composer = account, account.composer
        self._bindings = (
            account,
            account.engine,
            account.coordinator,
            self.composer.daily,
            self.composer.producer_history,
        )
        self._completed: WeakValueDictionary[int, CommittedSimulationAttemptBatch] = (
            WeakValueDictionary()
        )
        self._completed_fields: dict[int, tuple[object, ...]] = {}
        self._dispatch_lock = Lock()
        self._dispatch_publications: set[tuple[str, str]] = set()
        self._delivery_claims: set[tuple[str, str]] = set()

    def publish(
        self, prepared: PreparedContinuousCommit, *, fence: AccountFence
    ) -> ContinuousAccountReceipt:
        return self._publish(prepared, fence=fence)

    def _publish(
        self, prepared: PreparedContinuousCommit, *, fence: AccountFence
    ) -> ContinuousAccountReceipt:
        self._require_bindings()
        self.composer.require_prepared(prepared.composition)
        with self.account.write_transaction() as connection:
            receipt = self.account.commit_in_transaction(connection, prepared=prepared, fence=fence)
            self.composer.recheck_attempt_publication_in_transaction(
                connection, prepared, receipt, fence=fence
            )
        return receipt

    def _require_bindings(self) -> None:
        if self.account.composer is not self.composer or any(
            actual is not original
            for actual, original in zip(
                (
                    self.account,
                    self.account.engine,
                    self.account.coordinator,
                    self.composer.daily,
                    self.composer.producer_history,
                ),
                self._bindings,
                strict=True,
            )
        ):
            raise ValueError("ATTEMPT_PUBLICATION_OWNERS_CHANGED")

    def prepare_source(
        self,
        source: PreparedContinuousRuntimeAttemptSource,
        *,
        sources: SqlContinuousRuntimeAttemptSources,
    ) -> PreparedContinuousCommit:
        """Compose an original owned attempt source through the sole C/B reducers.

        Restored receipts and caller-created event records cannot enter this
        path. Preparation performs full original-source checks outside SQL;
        publication still owns the final current-state and deadline checks.
        """
        self._require_bindings()
        if (
            type(sources) is not SqlContinuousRuntimeAttemptSources
            or sources.accounts is not self.account
            or sources.daily is not self.composer.daily
            or sources.runtime_sources is not self.composer.producer_history
            or sources.preparer is not self.account.preparer
        ):
            raise ValueError("EXACT_ATTEMPT_SOURCE_OWNERS_REQUIRED")
        sources.require_prepared(source)
        if source.closure.kind not in (
            "pending",
            "activation",
            "unknown",
            "expired_unsent",
            "outcome",
        ):
            raise ValueError("SUPPORTED_ORIGINAL_ATTEMPT_SOURCE_REQUIRED")
        fence = source.source.fence.fence
        if sources.runtime_sources.current_fence() != fence:
            raise ValueError("ORIGINAL_ATTEMPT_SOURCE_OWNER_NO_LONGER_CURRENT")
        daily = self.composer.daily
        current = daily.resolve_snapshot(
            daily.read_attempt_snapshot(
                account_id=source.source.account_id,
                fence=fence,
                envelopes=source.envelopes,
                preparations=source.closure.preparations
                if source.closure.kind == "pending"
                else (),
            )
        )
        mutation = daily.prepare_attempt_mutation(
            current,
            dispatch_journal=sources.dispatch_journal if source.dispatch_appends else None,
            dispatch_appends=source.dispatch_appends,
        )
        transition = self.account.preparer.prepare_runtime_action(
            command_id=source.source.coordinator_command_id,
            checkpoint=source.previous.checkpoint,
            action=source.action,
        )
        prepared = self.account.prepare(
            transition,
            scope=source.previous.receipt.commit.scope,
            previous=source.previous,
            source_evidence=source.reference,
            attempts=mutation,
        )
        sources.require_prepared(source)
        return prepared

    def publish_dispatch(
        self, prepared: PreparedContinuousCommit, *, fence: AccountFence
    ) -> CommittedSimulationAttemptBatch:
        attempts = self.composer.inspect_prepared_attempt(prepared.composition)
        envelopes = attempts.snapshot.raw.requested_envelopes
        if (
            attempts.retry
            or not envelopes
            or attempts.journal is None
            or len(attempts.dispatch_appends) != len(envelopes)
            or any(
                item.event.state is not SubmissionAttemptState.IN_FLIGHT
                or item.event.dispatch is None
                for item in envelopes
            )
        ):
            raise ValueError("FRESH_COMPLETE_FIRST_SEND_PUBLICATION_REQUIRED")
        identity = (prepared.commit.scope.account_id, prepared.commit.transition.command_id)
        with self._dispatch_lock:
            if identity in self._dispatch_publications:
                raise ValueError("DISPATCH_PUBLICATION_ALREADY_ATTEMPTED")
            # Consume the publication opportunity before entering SQL. Even an
            # ambiguous COMMIT or lost return cannot mint another first-send
            # token by retrying this original preparation.
            self._dispatch_publications.add(identity)
        receipt = self._publish(prepared, fence=fence)
        # This line is reachable only after the actual outer SQL COMMIT returns.
        # A restored receipt, retry, lost acknowledgment or failed COMMIT never
        # enters this per-instance ownership registry.
        result = CommittedSimulationAttemptBatch(receipt, prepared, attempts)
        self._completed[id(result)] = result
        self._completed_fields[id(result)] = tuple(
            getattr(result, item.name) for item in fields(result)
        )
        finalize(result, self._completed_fields.pop, id(result), None)
        return result

    def require_completed(self, value: CommittedSimulationAttemptBatch) -> None:
        if (
            type(value) is not CommittedSimulationAttemptBatch
            or self._completed.get(id(value)) is not value
        ):
            raise ValueError("ORIGINAL_SUCCESSFUL_DISPATCH_COMMIT_REQUIRED")
        if any(
            getattr(value, item.name) is not original
            for item, original in zip(fields(value), self._completed_fields[id(value)], strict=True)
        ):
            raise ValueError("ORIGINAL_DISPATCH_COMMIT_FIELDS_CHANGED")
        if self.composer.inspect_prepared_attempt(value.account.composition) is not value.attempts:
            raise ValueError("ORIGINAL_DISPATCH_PREPARATION_CHANGED")

    def claim_delivery(self, value: CommittedSimulationAttemptBatch, *, attempt_id: str) -> None:
        """Consume one original first-send opportunity; this is not a freshness check.

        Shared by every delivery adapter using this original publisher. A failed
        or ambiguous venue call cannot restore this opportunity. Durable
        IN_FLIGHT still requires observation/recovery after process restart.
        """
        self.require_completed(value)
        if attempt_id not in {
            item.event.attempt_id for item in value.attempts.snapshot.raw.requested_envelopes
        }:
            raise ValueError("ORIGINAL_DISPATCH_ATTEMPT_REQUIRED")
        identity = (value.receipt.commit.semantic_sha256, attempt_id)
        with self._dispatch_lock:
            if identity in self._delivery_claims:
                raise ValueError("DISPATCH_DELIVERY_ALREADY_CONSUMED")
            self._delivery_claims.add(identity)
