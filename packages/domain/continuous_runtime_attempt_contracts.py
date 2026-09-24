"""Original source-only attempt closure; these records grant no delivery authority."""

from dataclasses import dataclass
from typing import ClassVar, Literal

from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountReceipt,
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.daily_attempt_contracts import (
    DailyAttemptEvent,
    DailyAttemptPreparation,
    DailyDispatchClaim,
)
from packages.domain.durable_journal_contracts import (
    JournalHead,
    JournalKey,
    JournalReceipt,
    empty_head,
)
from packages.domain.personal_contracts import ContractRecord
from packages.domain.stateful_venue_contracts import VenueSubmit
from packages.domain.submission_attempt import SubmissionAttemptState

RUNTIME_ATTEMPT_CLOSURE_SCHEMA = "continuous-attempt-closure/1"
RUNTIME_ATTEMPT_SOURCE_SCHEMA = "daily-attempt-accounting-source/1"
RUNTIME_ATTEMPT_OUTCOME_SCHEMA = "continuous-attempt-outcome/1"


@dataclass(frozen=True, slots=True, kw_only=True)
class ContinuousRuntimeOutcomeEvidence(ContractRecord):
    """Original activation result and actual independent captured registration."""

    contract_version: ClassVar[str] = "personal-continuous-attempt-outcome/1"
    attempt_id: str
    activation: ContinuousAccountReceipt
    activation_checkpoint: ContinuousEvidenceRef
    activation_source: ContinuousEvidenceRef
    capture: ContinuousEvidenceRef
    registration: VenueSubmit

    def __post_init__(self) -> None:
        super(ContinuousRuntimeOutcomeEvidence, self).__post_init__()
        transition = self.activation.commit.transition
        if (
            self.activation_checkpoint.schema_id != "continuous-checkpoint/1"
            or self.activation_checkpoint.object_ref != transition.checkpoint
            or self.activation_checkpoint.semantic_sha256 != transition.checkpoint_sha256
            or self.activation_source != self.activation.commit.source_evidence
            or self.activation_source.schema_id != RUNTIME_ATTEMPT_SOURCE_SCHEMA
            or self.capture.schema_id != "continuous-venue-capture/1"
            or self.attempt_id != self.registration.registration.submission.submission_attempt_id
        ):
            raise ValueError("OUTCOME_ORIGINAL_ACTIVATION_REFERENCE_DIFFERS")


@dataclass(frozen=True, slots=True, kw_only=True)
class ContinuousRuntimeAttemptClosure(ContractRecord):
    """Source facts precede the source hash, envelope, action and future C parent."""

    contract_version: ClassVar[str] = "personal-continuous-attempt-closure/1"
    kind: Literal["pending", "unknown", "activation", "expired_unsent", "outcome"]
    scope: ContinuousAccountScope
    previous: ContinuousAccountReceipt
    previous_checkpoint: ContinuousEvidenceRef
    events: tuple[DailyAttemptEvent, ...]
    preparations: tuple[DailyAttemptPreparation, ...]
    admission_records: tuple[ContinuousEvidenceRef, ...]
    descriptor: ContinuousEvidenceRef | None = None
    descriptor_receipt: JournalReceipt | None = None
    dispatch_keys: tuple[JournalKey, ...] = ()
    prior_dispatches: tuple[DailyDispatchClaim, ...] = ()
    unsent_dispatch_head: JournalHead | None = None
    unsent_dispatch_receipt: JournalReceipt | None = None
    outcome_reference: ContinuousEvidenceRef | None = None

    def __post_init__(self) -> None:
        super(ContinuousRuntimeAttemptClosure, self).__post_init__()
        ids = tuple(event.attempt_id for event in self.events)
        preparation_ids = tuple(item.attempt_id for item in self.preparations)
        if (
            not 1 <= len(ids) <= 4
            or ids != tuple(sorted(set(ids)))
            or preparation_ids != ids
            or len({event.recorded_at for event in self.events}) != 1
            or self.previous.commit.scope != self.scope
            or self.previous_checkpoint.schema_id != "continuous-checkpoint/1"
            or self.previous_checkpoint.object_ref != self.previous.commit.transition.checkpoint
            or self.previous_checkpoint.semantic_sha256
            != self.previous.commit.transition.checkpoint_sha256
            or not 1 <= len(self.admission_records) <= 4
            or len(set(self.admission_records)) != len(self.admission_records)
            or any(ref.schema_id != "daily-admission-producer/1" for ref in self.admission_records)
            or any(
                item.request.source_account_id != self.scope.account_id
                or item.request.source_account_binding_sha256 != self.scope.account_binding_sha256
                for item in self.preparations
            )
            or len(self.dispatch_keys) > 4
            or len(set(self.dispatch_keys)) != len(self.dispatch_keys)
            or len(self.prior_dispatches) > 4
        ):
            raise ValueError("ATTEMPT_ORIGINAL_SOURCE_INVENTORY_DIFFERS")
        states = {
            "pending": (SubmissionAttemptState.PENDING,),
            "unknown": (SubmissionAttemptState.UNKNOWN,),
            "activation": (SubmissionAttemptState.IN_FLIGHT,),
            "expired_unsent": (SubmissionAttemptState.ABANDONED,),
            "outcome": (SubmissionAttemptState.CONFIRMED, SubmissionAttemptState.RESOLVED),
        }[self.kind]
        if any(event.state not in states for event in self.events):
            raise ValueError("ATTEMPT_SOURCE_OPERATION_DIFFERS")
        if self.kind == "activation":
            if self.descriptor is None or self.descriptor_receipt is None:
                raise ValueError("ACTUAL_ACTIVATION_DESCRIPTOR_REQUIRED")
        elif self.descriptor is not None or self.descriptor_receipt is not None:
            raise ValueError("ATTEMPT_METADATA_CANNOT_CLAIM_ACTIVATION")
        if self.kind == "pending" and (self.dispatch_keys or self.prior_dispatches):
            raise ValueError("PENDING_SOURCE_CANNOT_CLAIM_DISPATCH")
        if self.kind == "unknown" and (
            tuple(claim.record.preparation.attempt_id for claim in self.prior_dispatches) != ids
            or not self.dispatch_keys
        ):
            raise ValueError("UNKNOWN_REQUIRES_ORIGINAL_DISPATCH_INVENTORY")
        if self.kind == "expired_unsent" and (
            len(self.events) != 1
            or self.events[0].unsent_proof is None
            or self.events[0].unsent_proof.reason != "expired"
            or self.events[0].unsent_proof.owner_command is not None
            or self.prior_dispatches
            or len(self.dispatch_keys) != 1
            or self.unsent_dispatch_head is None
            or self.unsent_dispatch_head.key_sha256 != self.dispatch_keys[0].semantic_sha256
            or (
                self.unsent_dispatch_receipt is None
                and self.unsent_dispatch_head != empty_head(self.dispatch_keys[0])
            )
            or (
                self.unsent_dispatch_receipt is not None
                and self.unsent_dispatch_receipt.committed_head != self.unsent_dispatch_head
            )
        ):
            raise ValueError("EXPIRED_UNSENT_REQUIRES_EXACT_ORIGINAL_DISPATCH_PREFIX")
        if self.kind != "expired_unsent" and (
            self.unsent_dispatch_head is not None or self.unsent_dispatch_receipt is not None
        ):
            raise ValueError("ATTEMPT_UNSENT_PREFIX_OPERATION_DIFFERS")
        if self.kind == "outcome":
            if (
                len(self.events) != 1
                or self.outcome_reference is None
                or self.outcome_reference.schema_id != RUNTIME_ATTEMPT_OUTCOME_SCHEMA
                or self.events[0].outcome is None
                or tuple(claim.record.preparation.attempt_id for claim in self.prior_dispatches)
                != ids
                or not self.dispatch_keys
            ):
                raise ValueError("OUTCOME_ORIGINAL_CAPTURE_AND_DISPATCH_REQUIRED")
        elif self.outcome_reference is not None:
            raise ValueError("OUTCOME_SOURCE_OPERATION_DIFFERS")
