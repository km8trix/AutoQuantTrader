"""Private authenticated statement retention, intentionally without HTTP/default wiring."""

from __future__ import annotations

from dataclasses import dataclass
from types import MethodType

from apps.api.operational_control_operator_preparation import OperatorStatementRecordPreparer
from packages.application.operational_control_operator_preparation import (
    PreparedOperationalControlOperatorStatementRecord,
)
from packages.domain.durable_journal_contracts import JournalHead
from packages.persistence.continuous_account import ResolvedContinuousAccount, SqlContinuousAccount
from packages.persistence.daily_runtime_risk import (
    ResolvedDailyRuntimeSnapshot,
    SqlDailyRuntimeRisk,
)
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.operator_statement_retention import StatementWriteOutcome


@dataclass(frozen=True, slots=True, repr=False)
class StatementDeliveryOutcome:
    write: StatementWriteOutcome
    delivery: str
    delivery_error: BaseException | None = None


class OperatorStatementRetentionService:
    """One fixed configured graph; no credentials enter persistence or results."""

    def __init__(
        self,
        preparer: OperatorStatementRecordPreparer,
        account: SqlContinuousAccount,
        daily: SqlDailyRuntimeRisk,
        journal: SqlDurableJournal,
    ) -> None:
        if (
            type(preparer) is not OperatorStatementRecordPreparer
            or type(account) is not SqlContinuousAccount
        ):
            raise ValueError("STATEMENT_EXACT_SERVICE_DEPENDENCIES_REQUIRED")
        self.preparer, self.account, self.daily, self.journal = preparer, account, daily, journal
        self._configuration = (
            preparer,
            account,
            daily,
            journal,
            account.coordinator._authority.clock,
            preparer.clock,
        )
        self._binding()

    def _binding(self) -> object:
        preparer, account, daily, journal, clock, clock_method = self._configuration
        if (
            self.preparer is not preparer
            or self.account is not account
            or self.daily is not daily
            or self.journal is not journal
            or self.account.coordinator._authority.clock is not clock
            or self.preparer.clock is not clock_method
            or type(clock_method) is not MethodType
            or clock_method.__self__ is not clock
            or clock_method.__func__ is not getattr(type(clock), "now", None)
        ):
            raise ValueError("STATEMENT_SHARED_CLOCK_BINDING_REQUIRED")
        return clock

    def retain(
        self,
        prepared: PreparedOperationalControlOperatorStatementRecord,
        *,
        current_account: ResolvedContinuousAccount,
        current_risk: ResolvedDailyRuntimeSnapshot,
        expected_statement_head: JournalHead,
        session_cookie: str | None,
        csrf_token: str,
    ) -> StatementDeliveryOutcome:
        clock = self._binding()
        # Authenticate ownership before reading supplied prepared fields; keep the
        # later admission sample separate, after every codec/preparation operation.
        self.preparer.require_prepared(
            prepared, session_cookie=session_cookie, csrf_token=csrf_token
        )
        candidate = self.account.prepare_statement_candidate(
            account=current_account,
            risk=current_risk,
            daily=self.daily,
            journal=self.journal,
            record=prepared.record,
            expected_head=expected_statement_head,
            prepared_at=prepared.checked_at,
        )
        observation = self.preparer.observe_prepared(
            prepared, session_cookie=session_cookie, csrf_token=csrf_token
        )
        self._binding()
        self.preparer.consume_admission(observation)
        request = self.account.prepare_statement_write(
            candidate,
            authenticated_at=observation.checked_at,
            expires_at=observation.expires_at,
            clock=clock,
        )
        outcome = self.account.retain_statement(request)
        if (
            outcome.primary is not None
            or outcome.cleanup != "verified_complete"
            or outcome.invocation_commit != "returned_successfully"
        ):
            return StatementDeliveryOutcome(outcome, "not_attempted")
        try:
            self._binding()
            self.preparer.require_prepared(
                prepared, session_cookie=session_cookie, csrf_token=csrf_token
            )
        except BaseException as error:
            return StatementDeliveryOutcome(outcome, "rejected_or_failed", error)
        return StatementDeliveryOutcome(outcome, "delivered")
