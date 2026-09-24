"""Versioned stateful submission provenance; constructing records grants no authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import ClassVar, Literal

from packages.domain.account_coordinator import AccountFence
from packages.domain.accounting_contracts import AccountSnapshot, Commitment
from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
from packages.domain.daily_runtime_contracts import (
    DailyRuntimeRiskEvidence,
    RuntimeCommitmentBinding,
    RuntimeRiskAdmission,
)
from packages.domain.decimal_math import exact_decimal_add, exact_decimal_multiply
from packages.domain.durable_journal_contracts import (
    MAX_RECORD_BYTES,
    JournalReceipt,
    journal_identifier,
)
from packages.domain.engine_contracts import DailyRiskDecision
from packages.domain.identifiers import canonical_id
from packages.domain.order_reducer import OrderSubmission, create_order_submission
from packages.domain.personal_contracts import ContractRecord, require_digest
from packages.domain.reconciliation_contracts import (
    OrderObservation,
    ReconciliationHeads,
    ReconciliationScope,
)
from packages.domain.research_job_contracts import ObjectRef
from packages.domain.stateful_venue_contracts import VenueSourceReference
from packages.domain.submission_attempt import SubmissionAttemptState


class DailyAttemptRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = "personal-daily-attempt/1"


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyFenceReference(DailyAttemptRecord):
    """A serializable receipt reference; the actual coordinator must revalidate it."""

    fence: AccountFence
    validated_at: datetime
    valid_until: datetime
    policy_sha256: str
    lease_sha256: str
    original_receipt_sha256: str

    def __post_init__(self) -> None:
        super(DailyFenceReference, self).__post_init__()
        self.fence.__post_init__()
        for value in (self.policy_sha256, self.lease_sha256, self.original_receipt_sha256):
            require_digest(value, "fence provenance")
        if self.validated_at >= self.valid_until:
            raise ValueError("fence reference lifetime is empty")


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyVenueSubmissionRequest(DailyAttemptRecord):
    """Exact canonical submission for the independent stateful venue only."""

    submission: OrderSubmission
    original_commitment: Commitment
    source_account_id: str
    source_account_binding_sha256: str
    venue_account_id: str
    venue_model: VenueSourceReference
    original_admission_sha256: str
    operation: Literal["submit"] = "submit"
    runtime_environment: Literal["stateful_simulation"] = "stateful_simulation"
    live_authorized: Literal[False] = False

    def __post_init__(self) -> None:
        super(DailyVenueSubmissionRequest, self).__post_init__()
        self.submission.__post_init__()
        self.original_commitment.__post_init__()
        for value in (self.source_account_id, self.venue_account_id):
            journal_identifier(value)
        for value in (self.source_account_binding_sha256, self.original_admission_sha256):
            require_digest(value, "request source")
        submission, hold = self.submission, self.original_commitment
        expected = create_order_submission(
            intent=submission.intent,
            risk_decision_id=submission.risk_decision_id,
            submission_attempt_id=canonical_id(
                "daily-runtime-attempt", submission.intent.intent_id
            ),
            submitted_at=submission.submitted_at,
        )
        if submission != expected:
            raise ValueError("request changed canonical order, client or daily attempt identity")
        if (
            hold.commitment_id != canonical_id("commitment", submission.intent.intent_id)
            or hold.intent_id != submission.intent.intent_id
            or hold.order_id != submission.order_id
            or hold.instrument_id != submission.intent.instrument_id
            or hold.symbol != submission.intent.symbol
            or hold.side is not submission.intent.side
            or hold.original_quantity != submission.intent.quantity
            or hold.remaining_quantity != hold.original_quantity
            or hold.filled_quantity != 0
            or hold.state != "approved_unsent"
            or hold.activated_at is not None
            or hold.activation_sequence is not None
            or hold.activation_frontier is not None
            or hold.terminal_reason is not None
        ):
            raise ValueError("request requires the exact original unsent canonical commitment")

    @property
    def attempt_id(self) -> str:
        return self.submission.submission_attempt_id


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyAttemptPreparation(DailyAttemptRecord):
    request: DailyVenueSubmissionRequest
    original_admission: RuntimeRiskAdmission
    admission_source: VenueSourceReference
    original_hold: RuntimeCommitmentBinding
    prepared_at: datetime

    def __post_init__(self) -> None:
        super(DailyAttemptPreparation, self).__post_init__()
        request, admission, hold = self.request, self.original_admission, self.original_hold
        if (
            not admission.decision.approved
            or admission.evidence.phase != "decision"
            or request.original_admission_sha256 != admission.semantic_sha256
            or self.admission_source.semantic_sha256_ref != hold.source_sha256
            or hold.commitment != request.original_commitment
            or hold.origin != "daily_runtime"
            or hold.account_id != request.source_account_id
            or admission.evidence.assignment.account_id != request.source_account_id
            or admission.evidence.assignment.account_binding_sha256
            != request.source_account_binding_sha256
            or request.submission.risk_decision_id != admission.decision.semantic_sha256
            or request.submission.intent not in admission.decision.batch.intents
            or hold.original_policy_sha256 != admission.decision.policy_sha256
            or not admission.recorded_at <= self.prepared_at < admission.expires_at
        ):
            raise ValueError("pending daily attempt sources or original validity differ")
        cash = dict(admission.decision.reserved_cash_by_intent)
        shares = dict(admission.decision.reserved_shares_by_intent)
        target = admission.decision.batch.target
        policy = admission.evidence.assignment.policy
        if (
            cash.get(hold.commitment.intent_id) != hold.commitment.reserved_cash
            or shares.get(hold.commitment.intent_id, 0) != hold.commitment.reserved_sell_quantity
            or hold.commitment.snapshot_sha256 != admission.evidence.snapshot_sha256
            or hold.commitment.source_session != target.trigger.source_session
            or hold.commitment.execution_session != target.trigger.execution_session
            or hold.commitment.not_before != target.not_before
            or hold.commitment.expires_at != target.expires_at
            or request.submission.submitted_at != target.trigger.as_of
            or hold.commitment.approved_price
            != exact_decimal_multiply(
                request.submission.intent.reference_price,
                exact_decimal_add(Decimal(1), policy.adverse_reserve_fraction),
            )
            or hold.commitment.remaining_fee_budget
            != exact_decimal_multiply(request.submission.intent.quantity, policy.fee_per_share)
        ):
            raise ValueError("original hold differs from the exact approved admission")

    @property
    def attempt_id(self) -> str:
        return self.request.attempt_id


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyActivationRecord(DailyAttemptRecord):
    """Fresh risk evidence; a replacement reserve still needs atomic application."""

    preparation_sha256: str
    request_sha256: str
    current_hold: RuntimeCommitmentBinding
    snapshot: AccountSnapshot
    evidence: DailyRuntimeRiskEvidence
    decision: DailyRiskDecision
    heads: ReconciliationHeads
    fence: DailyFenceReference
    checked_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        super(DailyActivationRecord, self).__post_init__()
        for value in (self.preparation_sha256, self.request_sha256):
            require_digest(value, "activation source")
        if (
            self.evidence.phase != "activation"
            or not self.decision.approved
            or self.decision.reasons
            or self.decision.evidence_sha256 != self.evidence.semantic_sha256
            or self.evidence.snapshot_sha256 != self.snapshot.semantic_sha256
            or self.decision.policy_sha256 != self.evidence.assignment.policy.semantic_sha256
            or self.evidence.inputs.heads != self.heads
            or self.snapshot.account_id != self.current_hold.account_id
            or self.fence.fence.account_id != self.snapshot.account_id
            or self.fence.fence.fencing_generation != self.heads.lease_generation
            or not self.fence.validated_at
            <= self.checked_at
            < self.expires_at
            <= self.fence.valid_until
            or self.expires_at > self.decision.batch.target.expires_at
            or self.checked_at != self.evidence.produced_at
        ):
            raise ValueError("activation identity, risk, fence or lifetime differs")


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyDispatchRecord(DailyAttemptRecord):
    command_id: str
    preparation: DailyAttemptPreparation
    activation: DailyActivationRecord
    previous_attempt_sha256: str
    dispatched_at: datetime

    def __post_init__(self) -> None:
        super(DailyDispatchRecord, self).__post_init__()
        journal_identifier(self.command_id)
        require_digest(self.previous_attempt_sha256, "dispatch predecessor")
        if (
            self.activation.preparation_sha256 != self.preparation.semantic_sha256
            or self.activation.request_sha256 != self.preparation.request.semantic_sha256
            or not self.activation.checked_at <= self.dispatched_at < self.activation.expires_at
        ):
            raise ValueError("dispatch requires exact fresh activation provenance")

    @property
    def record_id(self) -> str:
        return canonical_id("daily-dispatch-record", self.semantic_sha256)


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyDispatchClaim(DailyAttemptRecord):
    """Published data reference; this type never grants a process delivery token."""

    record: DailyDispatchRecord
    receipt: JournalReceipt
    record_ref: ObjectRef

    def __post_init__(self) -> None:
        super(DailyDispatchClaim, self).__post_init__()
        if (
            self.receipt.command_id != self.record.command_id
            or self.receipt.record_ids.count(self.record.record_id) != 1
            or self.record_ref.byte_count > MAX_RECORD_BYTES
        ):
            raise ValueError("dispatch claim record inventory differs")
        index = self.receipt.record_ids.index(self.record.record_id)
        if self.receipt.record_hashes[index] != self.record_ref.object_sha256:
            raise ValueError("dispatch record bytes differ from the journal receipt")


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyObservedOutcome(DailyAttemptRecord):
    scope: ReconciliationScope
    order: OrderObservation
    source: VenueSourceReference
    observed_at: datetime
    resolution: Literal["accepted", "rejected"]

    def __post_init__(self) -> None:
        super(DailyObservedOutcome, self).__post_init__()
        order = self.order
        if (
            self.scope.source_class != "stateful_simulation"
            or self.scope.environment != "stateful_simulation"
            or order.order_id is None
            or order.instrument_id is None
            or order.side is None
            or order.quantity is None
            or order.quantity <= 0
            or order.filled_quantity is None
            or not 0 <= order.filled_quantity <= order.quantity
        ):
            raise ValueError("outcome requires a positively identified stateful order")
        if self.resolution == "rejected":
            if order.status != "rejected" or order.filled_quantity != 0:
                raise ValueError("rejection requires explicit rejected order evidence")
        elif order.status not in ("working", "partial", "pending_cancel", "filled", "canceled"):
            raise ValueError("acceptance requires an observed known venue order")


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyUnsentProof(DailyAttemptRecord):
    """Locked-history descriptor; SQL must authenticate it before local release."""

    account_id: str
    attempt_id: str
    request_sha256: str
    attempt_history_sha256: str
    commitment_sha256: str
    heads: ReconciliationHeads
    fence: DailyFenceReference
    checked_at: datetime
    reason: Literal["expired", "revoked", "policy_cutover"]
    owner_command: VenueSourceReference | None

    def __post_init__(self) -> None:
        super(DailyUnsentProof, self).__post_init__()
        journal_identifier(self.account_id)
        journal_identifier(self.attempt_id)
        for value in (self.request_sha256, self.attempt_history_sha256, self.commitment_sha256):
            require_digest(value, "unsent proof source")
        if (
            self.fence.fence.account_id != self.account_id
            or self.fence.fence.fencing_generation != self.heads.lease_generation
            or not self.fence.validated_at <= self.checked_at < self.fence.valid_until
            or (self.reason != "expired" and self.owner_command is None)
        ):
            raise ValueError("unsent proof requires current scoped fence and owner provenance")


MAX_DAILY_ATTEMPT_EVENTS = 64


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyAttemptEvent(DailyAttemptRecord):
    attempt_id: str
    sequence: int
    previous_event_sha256: str | None
    state: SubmissionAttemptState
    recorded_at: datetime
    dispatch: DailyDispatchClaim | None = None
    outcome: DailyObservedOutcome | None = None
    unsent_proof: DailyUnsentProof | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        super(DailyAttemptEvent, self).__post_init__()
        journal_identifier(self.attempt_id)
        if not 1 <= self.sequence <= MAX_DAILY_ATTEMPT_EVENTS:
            raise ValueError("daily attempt sequence exceeds its bound")
        if (self.sequence == 1) != (self.previous_event_sha256 is None):
            raise ValueError("daily event predecessor differs")
        if self.previous_event_sha256 is not None:
            require_digest(self.previous_event_sha256, "attempt event predecessor")
        if self.reason is not None:
            journal_identifier(self.reason)
        expected = {
            SubmissionAttemptState.PENDING: (False, False, False, False),
            SubmissionAttemptState.IN_FLIGHT: (True, False, False, False),
            SubmissionAttemptState.CONFIRMED: (False, True, False, False),
            SubmissionAttemptState.UNKNOWN: (False, False, False, True),
            SubmissionAttemptState.RESOLVED: (False, True, False, False),
            SubmissionAttemptState.ABANDONED: (False, False, True, False),
        }[self.state]
        if (
            tuple(
                value is not None
                for value in (self.dispatch, self.outcome, self.unsent_proof, self.reason)
            )
            != expected
        ):
            raise ValueError("daily event payload differs from its exact lifecycle state")

    @property
    def event_id(self) -> str:
        return canonical_id("daily-attempt-event", self.semantic_sha256)


@dataclass(frozen=True, slots=True, kw_only=True)
class CanonicalDailyAttempt(DailyAttemptRecord):
    preparation: DailyAttemptPreparation
    events: tuple[DailyAttemptEvent, ...]

    def __post_init__(self) -> None:
        super(CanonicalDailyAttempt, self).__post_init__()
        from packages.domain.daily_attempt import _validate_daily_history

        _validate_daily_history(self.preparation, self.events)

    @property
    def attempt_id(self) -> str:
        return self.preparation.attempt_id

    @property
    def state(self) -> SubmissionAttemptState:
        return self.events[-1].state


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyAttemptEnvelope(DailyAttemptRecord):
    """Indexed event with a noncircular parent command and retained source closure."""

    account_id: str
    coordinator_command_id: str
    coordinator_sequence: int
    event: DailyAttemptEvent
    source_ref: ContinuousEvidenceRef

    def __post_init__(self) -> None:
        super(DailyAttemptEnvelope, self).__post_init__()
        journal_identifier(self.account_id)
        journal_identifier(self.coordinator_command_id)
        if not 1 <= self.coordinator_sequence < 2**63:
            raise ValueError("daily envelope account sequence is outside its bound")
        if self.source_ref.schema_id != "daily-attempt-accounting-source/1":
            raise ValueError("daily event requires its exact retained accounting source schema")


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyAttemptTransition(DailyAttemptRecord):
    attempt: CanonicalDailyAttempt
    disposition: Literal["applied", "idempotent"]
