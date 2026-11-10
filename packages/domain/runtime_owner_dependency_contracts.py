"""Source-only owner dependencies; typed records confer no assignment authority."""

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountReceipt,
    ContinuousAccountScope,
)
from packages.domain.daily_attempt_contracts import DailyFenceReference
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.domain.personal_contracts import ContractRecord, require_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.reconciliation_persistence_contracts import ReconciliationCommitReceipt

OWNER_DEPENDENCIES_SCHEMA = "runtime-owner-dependencies/1"
MAX_OWNER_DEPENDENCIES_BYTES = 256 * 1024


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeOwnerDependencies(ContractRecord):
    contract_version: ClassVar[str] = "personal-runtime-owner-dependencies/1"
    scope: ContinuousAccountScope
    previous: ContinuousAccountReceipt
    proposed: RuntimeRiskAssignment
    previous_assignment_sha256: str | None
    control_sha256: str | None
    obligations_sha256: str
    attempts_sha256: str
    heads: ReconciliationHeads
    fence: DailyFenceReference
    reconciliation: ReconciliationCommitReceipt | None
    checked_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        super(RuntimeOwnerDependencies, self).__post_init__()
        for value in (self.obligations_sha256, self.attempts_sha256):
            require_digest(value, "owner dependency inventory")
        for optional in (self.previous_assignment_sha256, self.control_sha256):
            if optional is not None:
                require_digest(optional, "owner dependency predecessor")
        if (
            self.previous.commit.scope != self.scope
            or self.proposed.account_id != self.scope.account_id
            or self.proposed.account_binding_sha256 != self.scope.account_binding_sha256
            or self.proposed.previous_assignment_sha256 != self.previous_assignment_sha256
            or self.heads.capacity_sha256 != self.obligations_sha256
            or self.heads.attempt_sha256 != self.attempts_sha256
            or self.heads.lease_generation != self.fence.fence.fencing_generation
            or self.fence.fence.account_id != self.scope.account_id
            or self.checked_at != self.fence.validated_at
            or not self.previous.recorded_at <= self.checked_at < self.valid_until
            or self.valid_until > self.fence.valid_until
            or self.proposed.effective_at > self.checked_at
        ):
            raise ValueError("owner dependency scope, inventory or original time differs")
        if self.reconciliation is not None and (
            self.reconciliation.commit.scope.account_id != self.scope.account_id
            or self.reconciliation.commit.scope.binding_sha256 != self.scope.account_binding_sha256
            or self.reconciliation.commit.scope.environment != "stateful_simulation"
        ):
            raise ValueError("owner dependency reconciliation scope differs")
