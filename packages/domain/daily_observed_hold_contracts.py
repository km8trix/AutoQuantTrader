"""Observed canonical hold provenance; no attempt outcome or dispatch authority."""

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from packages.domain.accounting_contracts import ExecutionPolicy
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.daily_attempt import reduce_daily_attempt
from packages.domain.daily_attempt_contracts import (
    CanonicalDailyAttempt,
    DailyAttemptEnvelope,
    DailyFenceReference,
)
from packages.domain.daily_runtime_contracts import (
    RuntimeCommitmentBinding,
    RuntimeObligationInventory,
)
from packages.domain.personal_contracts import ContractRecord, require_digest
from packages.domain.reconciliation_application_contracts import AppliedReconciliationBatch
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.research_job_contracts import require_identifier

OBSERVED_HOLD_SOURCE_SCHEMA = "daily-observed-hold-source/1"
OBSERVED_HOLD_GROUP_SCHEMA = "daily-observed-hold-group/1"


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeObservedHoldSource(ContractRecord):
    contract_version: ClassVar[str] = OBSERVED_HOLD_SOURCE_SCHEMA
    scope: ContinuousAccountScope
    coordinator_command_id: str
    coordinator_sequence: int
    previous_checkpoint: ContinuousEvidenceRef
    resulting_checkpoint: ContinuousEvidenceRef
    frontier: ContinuousEvidenceRef
    venue_capture: ContinuousEvidenceRef
    application_batches: tuple[ContinuousEvidenceRef, ...]
    source_closure_sha256: str
    heads: ReconciliationHeads
    fence: DailyFenceReference
    execution_policy: ExecutionPolicy
    applied_at: datetime
    checked_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        super(RuntimeObservedHoldSource, self).__post_init__()
        require_identifier(self.coordinator_command_id, "observed hold parent command")
        require_digest(self.source_closure_sha256, "observed source closure")
        if (
            not 1 <= self.coordinator_sequence < 2**63
            or self.fence.fence.account_id != self.scope.account_id
            or self.heads.lease_generation != self.fence.fence.fencing_generation
            or not self.applied_at <= self.checked_at < self.valid_until <= self.fence.valid_until
            or self.checked_at < self.fence.validated_at
            or self.execution_policy.model_id != "observed-facts-v1"
            or not 1 <= len(self.application_batches) <= 4096
            or len(set(self.application_batches)) != len(self.application_batches)
        ):
            raise ValueError(
                "observed hold source account, policy or original/current time differs"
            )


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyObservedHoldGroup(ContractRecord):
    contract_version: ClassVar[str] = OBSERVED_HOLD_GROUP_SCHEMA
    account_id: str
    coordinator_command_id: str
    coordinator_sequence: int
    source_ref: ContinuousEvidenceRef
    before_inventory_sha256: str
    after_inventory_sha256: str
    changed_hold_ids: tuple[str, ...]
    applied_at: datetime

    def __post_init__(self) -> None:
        super(DailyObservedHoldGroup, self).__post_init__()
        for value in (self.account_id, self.coordinator_command_id, *self.changed_hold_ids):
            require_identifier(value, "observed hold identity")
        for value in (self.before_inventory_sha256, self.after_inventory_sha256):
            require_digest(value, "observed hold inventory")
        if (
            not 1 <= self.coordinator_sequence < 2**63
            or self.source_ref.schema_id != OBSERVED_HOLD_SOURCE_SCHEMA
            or not 1 <= len(self.changed_hold_ids) <= 4096
            or self.changed_hold_ids != tuple(sorted(set(self.changed_hold_ids)))
            or self.before_inventory_sha256 == self.after_inventory_sha256
        ):
            raise ValueError("observed group requires a complete nonempty canonical hold delta")


@dataclass(frozen=True, slots=True)
class RuntimeObservedHoldInputs(ContractRecord):
    """Resolver output; exact original retained evidence must be authenticated separately."""

    source: RuntimeObservedHoldSource
    previous: CausalEngineCheckpoint
    resulting: CausalEngineCheckpoint
    frontier: ClosedEngineFrontier
    application_batches: tuple[AppliedReconciliationBatch, ...]


@dataclass(frozen=True, slots=True)
class DailyObservedHoldResult(ContractRecord):
    coordinator_command_id: str
    coordinator_sequence: int
    before: RuntimeObligationInventory
    after: RuntimeObligationInventory
    changed_bindings: tuple[RuntimeCommitmentBinding, ...]
    accounting_state_sha256: str
    group: DailyObservedHoldGroup | None


def daily_runtime_effect_watermark(
    *,
    attempt_envelopes: tuple[DailyAttemptEnvelope, ...],
    observed_groups: tuple[DailyObservedHoldGroup, ...],
) -> int:
    """Latest actual parent account sequence across complete retained effect histories."""
    if (
        type(attempt_envelopes) is not tuple
        or type(observed_groups) is not tuple
        or any(type(value) is not DailyAttemptEnvelope for value in attempt_envelopes)
        or any(type(value) is not DailyObservedHoldGroup for value in observed_groups)
    ):
        raise ValueError("effect watermark requires exact typed complete histories")
    return max(
        (
            *[item.coordinator_sequence for item in attempt_envelopes],
            *[item.coordinator_sequence for item in observed_groups],
        ),
        default=0,
    )


def daily_runtime_attempt_prefix(
    *,
    attempts: tuple[CanonicalDailyAttempt, ...],
    attempt_envelopes: tuple[DailyAttemptEnvelope, ...],
    through_coordinator_sequence: int,
) -> tuple[CanonicalDailyAttempt, ...]:
    """Replay original events through a retained parent sequence, never the latest head."""
    if (
        type(attempts) is not tuple
        or type(attempt_envelopes) is not tuple
        or type(through_coordinator_sequence) is not int
        or not 0 <= through_coordinator_sequence < 2**63
        or any(type(item) is not CanonicalDailyAttempt for item in attempts)
        or any(type(item) is not DailyAttemptEnvelope for item in attempt_envelopes)
    ):
        raise ValueError("attempt prefix requires exact immutable complete histories")
    by_id = {item.attempt_id: item for item in attempts}
    indexed = {(item.event.attempt_id, item.event.sequence): item for item in attempt_envelopes}
    events = {
        (item.attempt_id, event.sequence): event for item in attempts for event in item.events
    }
    if (
        len(by_id) != len(attempts)
        or len(indexed) != len(attempt_envelopes)
        or indexed.keys() != events.keys()
        or any(envelope.event != events[key] for key, envelope in indexed.items())
        or any(
            envelope.account_id
            != by_id[envelope.event.attempt_id].preparation.request.source_account_id
            for envelope in attempt_envelopes
        )
    ):
        raise ValueError("attempt prefix envelope inventory differs from canonical events")
    result = []
    for identity in sorted(by_id):
        attempt = by_id[identity]
        selected = tuple(
            event
            for event in attempt.events
            if indexed[(identity, event.sequence)].coordinator_sequence
            <= through_coordinator_sequence
        )
        sequences = tuple(
            indexed[(identity, event.sequence)].coordinator_sequence for event in attempt.events
        )
        if sequences != tuple(sorted(set(sequences))):
            raise ValueError("attempt parent sequences must preserve original event order")
        if selected:
            result.append(reduce_daily_attempt(attempt.preparation, selected))
    return tuple(result)
