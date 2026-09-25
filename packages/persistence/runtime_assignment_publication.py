"""Publish a source-qualified assignment inside the actual account transaction.

An assignment changes which future decisions may run. It does not manufacture a
new economic checkpoint or renew the original owner request's validity.
"""

from packages.domain.account_coordinator import AccountFence
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.daily_runtime_risk import PreparedDailyAssignment, SqlDailyRuntimeRisk


class RuntimeAssignmentPublicationError(ValueError):
    pass


class SqlRuntimeAssignmentPublication:
    def __init__(self, *, account: SqlContinuousAccount, daily: SqlDailyRuntimeRisk) -> None:
        if (
            type(account) is not SqlContinuousAccount
            or type(daily) is not SqlDailyRuntimeRisk
            or type(account.composer) is not SqlContinuousCommitComposer
            or type(daily.producers) is not SqlContinuousRuntimeSources
            or account.engine is not daily.engine
            or account.coordinator is not daily.coordinator
            or account.composer.daily is not daily
            or account.composer.producer_history is not daily.producers
        ):
            raise RuntimeAssignmentPublicationError("EXACT_RUNTIME_ASSIGNMENT_OWNERS_REQUIRED")
        self.account, self.daily = account, daily
        self._bindings = self._current_bindings()

    def _current_bindings(self) -> tuple[object, ...]:
        composer = self.account.composer
        if type(composer) is not SqlContinuousCommitComposer:
            raise RuntimeAssignmentPublicationError("RUNTIME_ASSIGNMENT_COMPOSER_CHANGED")
        return (
            self.account,
            self.daily,
            self.account.engine,
            self.daily.engine,
            self.account.coordinator,
            self.daily.coordinator,
            self.account.composer,
            self.daily.producers,
            composer.daily,
            composer.producer_history,
        )

    def publish(
        self, prepared: PreparedDailyAssignment, *, fence: AccountFence
    ) -> RuntimeRiskAssignment:
        actual = self._current_bindings()
        if any(a is not b for a, b in zip(actual, self._bindings, strict=True)):
            raise RuntimeAssignmentPublicationError("RUNTIME_ASSIGNMENT_OWNERS_CHANGED")
        self.daily.require_prepared_assignment(prepared)
        with self.account.write_transaction() as connection:
            installed = self.daily.install_prepared_in_transaction(
                connection, prepared, fence=fence
            )
            if installed is not prepared.result:
                raise RuntimeAssignmentPublicationError("ORIGINAL_INSTALLED_ASSIGNMENT_REQUIRED")
            checked = self.daily.recheck_installed_assignment_in_transaction(
                connection, prepared, fence=fence
            )
            if checked is not installed:
                raise RuntimeAssignmentPublicationError("PUBLISHED_ASSIGNMENT_READBACK_DIFFERS")
            receipt = self.account.coordinator.revalidate_for_commit_in_transaction(
                connection, fence
            )
            if receipt.validated_at >= prepared.valid_until:
                raise RuntimeAssignmentPublicationError("ASSIGNMENT_EXPIRED_BEFORE_COMMIT")
        return installed
