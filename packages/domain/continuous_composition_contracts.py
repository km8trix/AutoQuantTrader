"""Retained composition evidence; these records grant no runtime permission."""

from dataclasses import dataclass
from typing import ClassVar

from packages.domain.continuous_engine_contracts import ContinuousDecision, ContinuousEngineInputs
from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
from packages.domain.daily_attempt_contracts import DailyAttemptEnvelope
from packages.domain.daily_observed_hold_contracts import DailyObservedHoldGroup
from packages.domain.daily_runtime_contracts import RuntimeObligationInventory
from packages.domain.operational_control import OperationalControlTransition
from packages.domain.personal_contracts import ContractRecord, require_digest
from packages.domain.reconciliation_contracts import FactApplication, ReconciliationHeads
from packages.domain.research_dataset import ResearchDataClass
from packages.domain.research_job_contracts import require_identifier

SYNTHETIC_BOOTSTRAP_SCHEMA = "continuous-synthetic-bootstrap/1"
FORWARD_CLOSURE_SCHEMA = "continuous-forward-closure/1"
VENUE_CAPTURE_CLOSURE_SCHEMA = "continuous-venue-capture/1"
COMPOSITION_EVIDENCE_SCHEMA = "continuous-composition-evidence/1"


class ContinuousCompositionRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = "personal-continuous-composition/1"


@dataclass(frozen=True, slots=True)
class SyntheticContinuousBootstrap(ContinuousCompositionRecord):
    """Exact synthetic inputs only; never an entitlement or actual-source proof."""

    inputs: ContinuousEngineInputs

    def __post_init__(self) -> None:
        super(SyntheticContinuousBootstrap, self).__post_init__()
        if self.inputs.spec.source_mode != "synthetic_observed" or any(
            event.provenance.data_class != ResearchDataClass.SYNTHETIC_FIXTURE
            for event in self.inputs.bootstrap_events
        ):
            raise ValueError("SYNTHETIC_BOOTSTRAP_CANNOT_PROMOTE_PROVIDER_INPUTS")


@dataclass(frozen=True, slots=True)
class ContinuousAdmissionReference(ContinuousCompositionRecord):
    command_id: str
    request_sha256: str
    record_sha256: str
    payload_sha256: str
    admission_sha256: str
    commitments_sha256: str
    producer_closure: ContinuousEvidenceRef

    def __post_init__(self) -> None:
        super(ContinuousAdmissionReference, self).__post_init__()
        require_identifier(self.command_id, "original admission command")
        for name in (
            "request_sha256",
            "record_sha256",
            "payload_sha256",
            "admission_sha256",
            "commitments_sha256",
        ):
            require_digest(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class ContinuousCompositionEvidence(ContinuousCompositionRecord):
    previous_checkpoint_sha256: str | None
    checkpoint_sha256: str
    new_decisions: tuple[ContinuousDecision, ...]
    admissions: tuple[ContinuousAdmissionReference, ...]
    expected_heads: ReconciliationHeads
    resulting_heads: ReconciliationHeads
    before_obligations: RuntimeObligationInventory
    after_obligations: RuntimeObligationInventory
    control: OperationalControlTransition | None
    benchmark_instrument_id: str | None
    applications: tuple[FactApplication, ...] = ()
    observed_holds: DailyObservedHoldGroup | None = None
    attempt_envelopes: tuple[DailyAttemptEnvelope, ...] = ()

    def __post_init__(self) -> None:
        super(ContinuousCompositionEvidence, self).__post_init__()
        if self.previous_checkpoint_sha256 is not None:
            require_digest(self.previous_checkpoint_sha256, "previous checkpoint")
        require_digest(self.checkpoint_sha256, "checkpoint")
        if len(self.new_decisions) > 4 or len(self.admissions) > 4:
            raise ValueError("CONTINUOUS_COMPOSITION_DECISION_BOUND")
        applications = tuple(value.fact_id for value in self.applications)
        if len(applications) > 4096 or applications != tuple(sorted(set(applications))):
            raise ValueError("CONTINUOUS_APPLICATION_INVENTORY_DIFFERS")
        ids = tuple(ref.command_id for ref in self.admissions)
        if len(set(ids)) != len(ids):
            raise ValueError("CONTINUOUS_COMPOSITION_DUPLICATE_ADMISSION")
        if self.attempt_envelopes:
            first = self.attempt_envelopes[0]
            if (
                len(self.attempt_envelopes) > 4
                or self.new_decisions
                or self.admissions
                or self.applications
                or self.observed_holds is not None
                or tuple(item.event.attempt_id for item in self.attempt_envelopes)
                != tuple(sorted({item.event.attempt_id for item in self.attempt_envelopes}))
                or any(
                    (
                        item.account_id,
                        item.coordinator_command_id,
                        item.coordinator_sequence,
                        item.source_ref,
                    )
                    != (
                        first.account_id,
                        first.coordinator_command_id,
                        first.coordinator_sequence,
                        first.source_ref,
                    )
                    for item in self.attempt_envelopes
                )
                or self.resulting_heads.effect_watermark != first.coordinator_sequence
                or self.expected_heads.effect_watermark >= first.coordinator_sequence
            ):
                raise ValueError("CONTINUOUS_ATTEMPT_GROUP_BINDING_DIFFERS")
        if self.observed_holds is not None and (
            self.new_decisions
            or self.admissions
            or not self.applications
            or self.observed_holds.before_inventory_sha256
            != self.before_obligations.semantic_sha256
            or self.observed_holds.after_inventory_sha256 != self.after_obligations.semantic_sha256
            or self.resulting_heads.effect_watermark != self.observed_holds.coordinator_sequence
            or self.expected_heads.attempt_sha256 != self.resulting_heads.attempt_sha256
        ):
            raise ValueError("CONTINUOUS_OBSERVED_HOLD_GROUP_BINDING_DIFFERS")
        if self.benchmark_instrument_id is not None:
            require_identifier(self.benchmark_instrument_id, "benchmark instrument")
        if (
            self.expected_heads.capacity_sha256 != self.before_obligations.semantic_sha256
            or self.resulting_heads.capacity_sha256 != self.after_obligations.semantic_sha256
            or self.expected_heads.control_revision
            != (0 if self.control is None else self.control.sequence_number)
            or self.resulting_heads.control_revision != self.expected_heads.control_revision
            or self.resulting_heads.lease_generation != self.expected_heads.lease_generation
        ):
            raise ValueError("CONTINUOUS_COMPOSITION_CAPACITY_BINDING_DIFFERS")
